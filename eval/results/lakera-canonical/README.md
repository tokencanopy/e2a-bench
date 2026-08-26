# lakera-canonical — Lakera Guard on the PI task

Curated metrics for the commercial **Lakera Guard** prompt-injection detector, run on the
**same canonical segment input** as `ours-canonical/` so the row is directly comparable.
Only `metrics.json` is committed; raw per-entry predictions stay gitignored under
`eval/runs/lakera/`.

## What this is
- **Detector:** Lakera Guard `POST /v2/guard/results`, reading the `prompt_attack` detector
  (see `eval/detectors/lakera.py`). Request: the flattened canonical segment blob as a single
  user message `{"messages":[{"role":"user","content":text}]}`.
- **Task:** `pi` (PI positives vs. genuinely-benign negatives; phishing excluded from the FP
  denominator, reported separately as `cross_fire`).
- **Corpus:** 4,833 in-scope (2,794 PI pos / 2,039 benign neg). Coverage 1.0, **0 errors**
  (and 0 errors on the full 1,500-msg phishing cross-fire slice — no HTML-parse failures).

## Headline (task=pi, PI vs benign)
| metric | value |
|---|---|
| Recall @0.35 | 0.67 |
| FPR @0.35 | 0.05 |
| Precision @0.35 | 0.95 |
| AUC-ROC | 0.83 |
| AUC-PR | 0.86 |
| TPR@1%FPR | 0.000 |
| cross-fire (phishing) | 0.159 |
| latency p50 / p95 | 134 ms / 215 ms |

**Caught 1,879 / 2,794 injections (67.3%)** at threshold 0.35 — concentrated in the overt
families: AgentDojo 91% (1,304/1,440), handcrafted 90% (52/58), but LLMail-Inject 46%
(371/800) and InjecAgent 31% (152/496). Direct 46% / indirect 79%. Highest precision (0.95)
and lowest cross-fire (0.16) of the three commercial APIs; fastest (p50 134 ms).

## Caveat carried into the paper — coarse ordinal score
Lakera's `prompt_attack` verdict is a **5-level ordinal confidence band**
(`l1_confident` … `l5_unlikely`), mapped to {1.0, 0.75, 0.5, 0.25, 0.0}. Like Model Armor's
3-level categorical, this is **coarse**: AUC-ROC / TPR@low-FPR are coarser than the
continuous-score detectors, and TPR@1%FPR degenerates to **0.000** even though within the
plaintext surface it reaches 0.55. Recall/FPR at 0.35 are unaffected.

## Profile vs the other commercial APIs
The best-behaved commercial PI detector (highest precision, low FPR, fast, a genuine PI
product — unlike ScamGuard's off-label scam detector) but the **same signature-not-concept
failure**: strong on overt AgentDojo (91%), collapsing on the naturalistic tail (31–46%).
Sits in Model Armor's "conservative/precise" bucket, at much higher recall (0.67 vs 0.28) and
AUC (0.83 vs 0.63).

| | Model Armor | ScamGuard | Lakera |
|---|---|---|---|
| AUC-ROC | 0.63 | 0.85 | 0.83 |
| Recall @0.35 | 0.28 | 0.71 | 0.67 |
| FPR | 0.03 | 0.16 | 0.05 |
| Precision | 0.93 | 0.86 | 0.95 |
| TPR@1%FPR | 0.092 | 0.000 | 0.000 |
| cross-fire | 0.18 | 0.52 | 0.16 |

## Per-surface AUC-ROC (task=pi)
| surface | AUC |
|---|---|
| plaintext (body) | 0.86 |
| header / subject | 0.67 |
| html (visible) | 0.80 |
| html hidden (CSS) | 0.78 |
| multipart mismatch | 0.80 |
| encoded / obfuscated | 0.52 |
| quoted thread | 0.76 |
| overall | 0.83 |

## Reproduce
```
export LAKERA_API_KEY=...                             # Lakera Guard key
export LAKERA_API_URL=https://api.lakera.ai/v2/guard/results
export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl      # piguard-eval --dump-segments
eval/.venv/bin/python eval/run_eval.py --manifest eval/combined_manifest.jsonl \
    --detectors lakera --workers 4 --out-dir eval/runs/lakera
eval/.venv/bin/python eval/grade.py --run-dir eval/runs/lakera --task pi --slice surface
```

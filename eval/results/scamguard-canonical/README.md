# scamguard-canonical — ScamGuard (checkreality.ai) on the PI task

Curated metrics for the commercial **ScamGuard** scam/phishing detector, run on the
**same canonical segment input** as `ours-canonical/` so the row is directly comparable.
Only `metrics.json` is committed; raw per-entry predictions stay gitignored under
`eval/runs/scamguard/`.

## What this is
- **Detector:** ScamGuard / checkreality.ai `POST /v1/inbound/scan` (API v0.1.0). Sends the
  flattened canonical segment blob as `raw_email` with `content_type=text/plain`; parses the
  `{verdict, score, signals}` response (see `eval/detectors/scamguard.py`).
- **Task:** `pi` (PI positives vs. genuinely-benign negatives; phishing excluded from the FP
  denominator, reported separately as `cross_fire`).
- **Off-label note:** ScamGuard is a **scam/phishing** product, not a PI detector. We run it
  on the PI task for a like-for-like commercial comparison; read its numbers as "how well
  does a scam detector rank prompt injections," not as its designed use.
- **Corpus:** 4,833 in-scope (2,794 PI pos / 2,039 benign neg). Coverage 1.0, **0 errors on
  the PI task**.

## Headline (task=pi, PI vs benign)
| metric | value |
|---|---|
| Recall @0.35 | 0.71 |
| FPR @0.35 | 0.16 |
| Precision @0.35 | 0.86 |
| AUC-ROC | 0.85 |
| AUC-PR | 0.88 |
| TPR@1%FPR | 0.000 |
| TPR@0.1%FPR | 0.000 |
| cross-fire (phishing) | 0.524 |
| latency p50 / p95 | 382 ms / 5,118 ms |

**Caught 1,987 / 2,794 injections (71.1%)** at threshold 0.35 — and unlike Model Armor it is
*not* confined to the overt family: AgentDojo 82% (1,182/1,440), handcrafted 78% (45/58),
LLMail-Inject 64% (508/800), InjecAgent 51% (252/496). Highest AUC-ROC of any non-LLM
detector (0.85, above the OSS ensemble's 0.82).

## Caveat carried into the paper — the mirror image of Model Armor
The high AUC is **scam-correlation, not PI understanding**: ScamGuard fires on "scamminess,"
which injections and phishing share. It is **miscalibrated for low-FPR use** — TPR@1%FPR and
TPR@0.1%FPR are both **0.000**, and at its own 0.35 threshold it runs at a **16% FPR**. It
also cross-fires on **52%** of phishing (vs Model Armor's 17.5%). So where Model Armor is
conservative/precise but blind to the naturalistic tail, ScamGuard is aggressive/high-recall
but unusable at any deployable operating point. Neither is a usable PI detector.

## HTTP 500 robustness issue (29 inputs)
29 of the 1,500 phishing `.eml` (all HTML-heavy Nazario messages) deterministically return
**HTTP 500** from the API; the same content returns 200 once HTML tags are stripped, so it is
a server-side HTML-parse bug, not bad input (see `scamguard-500-bug-report.md` in this dir).
These fall entirely in the phishing set (out of scope for the PI pos/neg), so the PI task has
**0 errors / coverage 1.0**; the cross-fire phishing slice is 1,471 scored (1,500 − 29).

## Per-surface AUC-ROC (task=pi)
| surface | AUC |
|---|---|
| plaintext (body) | 0.88 |
| header / subject | 0.76 |
| html (visible) | 0.79 |
| html hidden (CSS) | 0.85 |
| multipart mismatch | 0.83 |
| encoded / obfuscated | 0.62 |
| quoted thread | 0.81 |
| overall | 0.85 |

(PDF-attachment surface omitted from the paper table, same as the OSS detectors: the
extractor surfaces raw `%PDF` bytes.)

## Reproduce
```
export SCAMGUARD_API_KEY=...                          # pilot key (checkreality.ai)
export SCAMGUARD_API_URL=https://api.checkreality.ai/v1/inbound/scan
export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl      # piguard-eval --dump-segments
eval/.venv/bin/python eval/run_eval.py --manifest eval/combined_manifest.jsonl \
    --detectors scamguard --workers 4 --out-dir eval/runs/scamguard
eval/.venv/bin/python eval/grade.py --run-dir eval/runs/scamguard --task pi --slice surface
```
Note: the pilot API rate-limits aggressively (HTTP 429) above ~4 concurrent workers; drop to
`--workers 1` for the final retry pass so the backoff clears the 429s.

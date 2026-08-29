# modelarmor-canonical — Google Cloud Model Armor on the PI task

Curated metrics for the commercial **Model Armor** PI/jailbreak detector, run on the
**same canonical segment input** as `ours-canonical/` so the row is directly comparable.
Only `metrics.json` is committed; raw per-entry predictions stay gitignored under
`eval/runs/modelarmor/`.

## What this is
- **Detector:** Google Cloud Model Armor `sanitizeUserPrompt`, `pi_and_jailbreak` filter
  (v1), template `e2a` in the `us` multi-region of project `e2a-protocol`. Called via
  Application Default Credentials (see `eval/detectors/modelarmor.py`).
- **Task:** `pi` (PI positives vs. genuinely-benign negatives; phishing excluded from the
  FP denominator, reported separately as `cross_fire`).
- **Detector input:** the canonical piguard segment dump (`PIGUARD_SEGMENTS`), flattened to
  text and sent as `userPromptData.text` — identical to what the OSS detectors screen.
- **Corpus:** 4,833 in-scope (2,794 PI pos / 2,039 benign neg). Coverage 1.0, **0 errors on
  the PI task** (1 phishing entry, `nazario_1903`, returned HTTP 400 and is dropped from the
  1,500-msg cross-fire slice → 1,499).

## Headline (task=pi, PI vs benign)
| metric | value |
|---|---|
| Recall @0.35 | 0.28 |
| FPR @0.35 | 0.03 |
| Precision @0.35 | 0.93 |
| AUC-ROC | 0.63 |
| AUC-PR | 0.68 |
| TPR@1%FPR | 0.092 |
| cross-fire (phishing) | 0.175 |

**Caught 795 / 2,794 injections (28.5%)** — ~87% of them from the overt AgentDojo family
(688/1,440 = 48%), vs 6–8% of the naturalistic InjecAgent (42/496) / LLMail-Inject (50/800)
attacks. Conservative and precise (lowest FPR of any baseline, best single-detector
TPR@1%FPR) but blind to the naturalistic tail — the same signature-not-concept profile as
Meta Prompt Guard 2, now in a purpose-built commercial product.

## Caveat carried into the paper
Model Armor returns only a **3-level categorical confidence** (`HIGH`/`MEDIUM`, else no
match) → scores collapse to {0.0, 0.75, 1.0}, so its AUC-ROC / TPR@1%FPR are **coarser**
than the continuous-score detectors. Recall/FPR at 0.35 are unaffected. Below chance (0.49)
on the encoded/obfuscated surface.

## Reproduce
```
export MODELARMOR_PROJECT=e2a-protocol MODELARMOR_LOCATION=us MODELARMOR_TEMPLATE=e2a
export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl      # piguard-eval --dump-segments
gcloud auth application-default login                 # ADC; user cred is fine
eval/.venv/bin/python eval/run_eval.py --manifest eval/paper_manifest.jsonl \
    --detectors modelarmor --workers 6 --out-dir eval/runs/modelarmor
eval/.venv/bin/python eval/grade.py --run-dir eval/runs/modelarmor --task pi --slice surface
```
Note: the gcloud CLI may be blocked by a VPC-SC perimeter on `e2a-protocol` even when the
ADC data-plane call (`sanitizeUserPrompt`) succeeds — verify via the API, not the CLI.

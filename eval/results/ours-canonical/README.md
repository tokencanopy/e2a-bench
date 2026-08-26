# ours-canonical — per-surface PI detection (canonical segment input)

Curated metrics for "our" eval architecture (task-aware grading + segment-faithful
detector input). Raw per-entry prediction JSONL stays gitignored under
`eval/runs/offline-oss/`; only `metrics.json` is committed here.

## What this is
- **Task:** `pi` (prompt-injection positives vs. genuinely-benign negatives;
  phishing excluded from the FP denominator, reported separately as `cross_fire`).
- **Detector input:** the canonical piguard segment dump (`PIGUARD_SEGMENTS`), so
  detectors screen exactly what piguard sees — including hidden HTML and
  `attachment_text`. This is what makes the `pdf_attachment` surface measurable.
- **Detectors (full OSS set):** DeBERTa-v3, InjecGuard, Llama-Prompt-Guard-2-86M,
  DistilBERT (degenerate), and piguard. **0 errors, coverage 1.0** for all five.
- **Corpus:** 4,833 in-scope (2,794 PI pos / 2,039 benign neg) from the 6,333-entry
  combined manifest.

## Headline (task=pi, PI vs benign)
| detector | AUC-ROC | AUC-PR | TPR@1%FPR | cross-fire (phishing) |
|---|---|---|---|---|
| DeBERTa-v3 | **0.81** | 0.82 | 0.05 | 0.32 |
| InjecGuard | 0.78 | 0.81 | 0.05 | 0.36 |
| Llama-Prompt-Guard-2 | 0.72 | 0.79 | **0.08** | 0.01 |
| piguard | 0.64 | 0.68 | 0.03 | 0.32 |
| DistilBERT | 0.53 (degenerate) | 0.55 | 0.00 | 1.00 |

**Per-surface (Table `tab:per-surface`): no single detector dominates** — the best
model flips with the carriage. DeBERTa leads on plaintext (0.83) but collapses to
0.39 on PDF attachments; InjecGuard leads on html/multipart/hidden-CSS (0.80–0.89);
Llama-Prompt-Guard-2 leads on the hardest surfaces (pdf 0.85, encoded 0.84).

## Caveats (carried into the paper)
- **PDF surface is textual-PDF only.** Dataset PDFs are uncompressed/plaintext, and
  `attachment_text` carries the **raw PDF byte stream** (`%PDF-1.4 …`), not extracted
  prose — DeBERTa's sub-chance 0.39 reflects that, not deep-PDF coverage.
- **Per-surface TPR@low-FPR omitted** — ~25 negatives/surface, below the 1/n_neg floor.
- **DistilBERT degenerate** — flags ~everything (FPR 0.98); exclude from conclusions.
- **piguard built from `e2a@7b3b1af`** (current HEAD), not the pinned `fe60124`.

## Reproduce
```
export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl     # piguard-eval --dump-segments
export HF_TRUST_REMOTE_CODE=1                         # InjecGuard custom arch
# (HF_TOKEN in .env for the gated Llama model)
eval/.venv/bin/python eval/run_eval.py --manifest eval/combined_manifest.jsonl \
    --detectors hf:protectai/deberta-v3-base-prompt-injection-v2 \
    --detectors hf:fmops/distilbert-prompt-injection \
    --detectors hf:leolee99/InjecGuard \
    --detectors hf:meta-llama/Llama-Prompt-Guard-2-86M \
    --detectors piguard --piguard-bin eval/piguard-eval-bin \
    --hf-batch-size 16 --out-dir eval/runs/offline-oss
eval/.venv/bin/python eval/grade.py --run-dir eval/runs/offline-oss --task pi --slice surface
```

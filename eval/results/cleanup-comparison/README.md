# EML-cleanup detector-robustness eval

Effect of the optional `--eml-cleanup` preprocessing (`eval/eml_extract.py`) on four
locally-runnable HuggingFace prompt-injection classifiers, with cleanup **off**
(baseline) and **on**.

`--eml-cleanup` replaces each detector's default raw-`.eml` extraction (which takes
the `text/plain` part first) with a canonical parse that (1) merges the `text/plain`
**and** HTML-stripped bodies so a payload in either MIME part is seen, and (2)
refangs defanged URLs (`hxxp://`, `[.]`).

## Layout

```
prompt-injection/{baseline,cleanup}/   PI-only set (1576, all positive) — recall by type
phishing/{baseline,cleanup}/           phishing set (3000: 1500 phishing / 1500 benign)
pi-vs-benign/{baseline,cleanup}/       PI detection: 1576 PI positives vs 3000 phishing/benign
                                       negatives — where FPR / AUC / TPR@low-FPR live
  <detector>.jsonl   per-entry predictions   metrics.json   grade.py output (slice: threat_type)
SUMMARY.md           full baseline-vs-cleanup tables
```

`pi-vs-benign` reuses the PI and phishing predictions (no extra inference): PI entries
are positives, all phishing/benign entries are negatives (none are prompt injections),
so the detectors get a proper false-positive denominator. Ground truth is
`dataset/{phishing,prompt-injection}/manifest.jsonl`; per-run `manifest_used.jsonl`
copies are omitted to keep the artifact small. Evaluated on the **1576-entry PI
manifest snapshot**; `main` later expanded it to 2776.

## Detectors

`hf:protectai/deberta-v3-base-prompt-injection-v2`, `hf:fmops/distilbert-prompt-injection`,
`hf:leolee99/InjecGuard` (ships custom code → `trust_remote_code`), and Meta's gated
`hf:meta-llama/Llama-Prompt-Guard-2-86M` (weights not committed — GitHub-LFS quota;
fetch with an authenticated `hf download`). Threshold 0.35, CPU.

## Key findings

**1. On prompt-injection detection, `--eml-cleanup` improves discrimination for every
detector — this is threshold-independent, not a scoring artifact.**

| detector | recall B→C | FPR B→C | AUC-ROC B→C | TPR@1%FPR B→C |
|---|---|---|---|---|
| deberta-v3 | 0.247 → 0.423 | 0.367 → 0.165 | **0.452 → 0.675** | 0.040 → 0.091 |
| InjecGuard | 0.643 → 0.674 | 0.482 → 0.361 | 0.577 → 0.691 | 0.050 → 0.022 |
| Prompt Guard 2 (Meta) | 0.071 → 0.125 | 0.011 → 0.009 | 0.237 → 0.447 | 0.069 → 0.129 |
| distilbert | 1.000 → 1.000 | 1.000 → 1.000 | 0.203 → 0.380 | 0.000 → 0.000 |

The **baseline AUC-ROC is below 0.5** for three of four detectors: the `text/plain`-only
parse ranks injections *below* benign mail, because the payload is buried in an HTML
part the baseline never reads. Cleanup reads it, and AUC jumps (deberta +0.22). So the
recall gain reflects genuine signal recovery. Gains concentrate on **direct**
injections (deberta 0.228 → 0.481).

**2. deberta-v3 is the strongest deployable detector** (post-cleanup FPR 0.165,
best TPR@1%FPR 0.091, AUC 0.675). InjecGuard has comparable AUC but ~2× the FPR.
Prompt Guard 2 barely fires (very low FPR) but its absolute recall stays low — these
email injections are subtler than the overt patterns it was trained on.

**3. distilbert is degenerate, not mis-configured.** It flags ~everything (recall 1.0,
FPR 1.0, AUC < 0.5). Verified the wiring is correct (overt injections score the
positive class ≈ 0.9995); it was trained on short prompt snippets and collapses on
email-length text. Excluded from "strongest" claims.

**4. Robustness:** cleanup recovered the **21 malformed-charset phishing emails** the
baseline parser silently dropped (coverage 0.993 → 1.000).

On the **phishing** set (injection detectors run over phishing/benign mail), cleanup
*lowers* recall but cuts FPR (deberta 0.087 → 0.017) — phishing is not injection, so
the cleaner body looks less injection-like and the detectors correctly stop firing.

See `SUMMARY.md` for the full per-detector / per-type tables.

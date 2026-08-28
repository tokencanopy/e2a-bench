# Evaluation methodology — recommendations for the detection harness

> Research note (for the eval owner to review — **not** a code change). Audits `run_eval.py` / `grade.py`
> against how PI/phishing **detection** is evaluated in the literature, and recommends a reporting protocol.
> Findings are adversarially verified against primary sources; self-reported and refuted items flagged.

## TL;DR — the current setup's weak point
`grade.py` leads with **ROC-AUC + a single fixed 0.35 threshold**. For an imbalanced gateway detector
(benign ≫ malicious), the literature is unanimous that this is the wrong headline:
- **Lead with TPR at a fixed *low* FPR** (1% / 0.5% / 0.1%) + **PR-AUC**; keep ROC-AUC only as a comparability column.
- **A single fixed 0.35 threshold is indefensible if 0.35 was chosen by looking at the test set** — calibrate on a held-out validation split and report the **full ROC/PR curve**.
- Detectors emit **incomparable score scales** (Go heuristic vs HF logit vs LLM-judge vs Lakera/Model-Armor) → don't threshold them all at 0.35; use per-detector curves + TPR@FPR (invariant to monotone rescaling).
- Add **bootstrap CIs**, especially on small-n per-slice (surface / threat_type) cells.

## 1. Recommended reporting protocol
| What | Recommendation | Why |
|---|---|---|
| **Lead metric** | **TPR @ {1%, 0.5%, 0.1%} FPR** per detector | base-rate problem: most email is benign, FPs are costly (PromptShield) |
| **Secondary** | **PR-AUC** (base-rate sensitive) | better than ROC-AUC for positive-minority detection |
| **Comparability only** | ROC-AUC | report it, don't lead with it |
| **Operating point** | FPR/FNR at the chosen threshold, **FPR measured on benign ham** | high AUC hides catastrophic operating points (PromptGuard AUC 0.92 / FPR 0.89) |
| **Threshold** | calibrate on a **validation split**, never test; show full ROC+PR curves | threshold-on-test is leakage (PromptShield's own retrospective) |
| **Heterogeneous scores** | per-detector ROC/PR + TPR@FPR (rescale-invariant); or per-detector calibration on val | 0.35 means different things to a heuristic vs an LLM judge |
| **Uncertainty** | **bootstrap CIs** on every metric; flag small-n slices | per-surface/threat_type cells are small |
| **System cost** | p50/p95 latency (+ throughput / $/call) as a **secondary** column | appropriate for a demo paper, but must not displace detection quality |

**Reading a `[0.000, x]` TPR@1%FPR interval.** Several intervals in
`results/tier1-analysis/table1_aligned.json` have a zero lower bound even where the
point estimate is high (e.g. judge:3.5-flash on PI: 0.811, CI `[0.000, 0.851]`). This
is a property of TPR-at-a-fixed-FPR on *discrete* scores, not a defect: `tpr_at_fpr()`
picks the strictest threshold whose FPR stays under target, and LLM judges emit a small
set of tied confidence values. In a bootstrap resample where the ties fall the wrong
way, that threshold lands above every positive and the statistic collapses to 0. Read
these intervals as "the operating point is unstable under resampling", and lead with
AUC for those rows. Fixing it means changing the estimator (interpolating across ties),
which would move the published point estimates — so the estimator is left as-is.

## 2. Prior-work numbers for the comparison / related-work table
*(self-reported on each paper's own benchmark — cite as such; "home-field advantage")*

**PromptShield (arXiv:2501.15145), Table 4 — TPR@FPR (the models we also benchmark):**
| Detector | AUC | TPR@1%FPR | TPR@0.1%FPR |
|---|---|---|---|
| **ProtectAI deberta-v3-v2** (we run this) | 0.705 | **1.97%** | **0.00%** |
| **InjecGuard** (we run this) | 0.765 | 20.37% | — |
| Fmops distilbert | 0.754 | 13.00% | — |
| Meta PromptGuard | 0.874 | 12.78% | 9.4% |
| PromptShield (Llama-3.1-8B) | 0.998 | 94.80% | 65.33% |

→ **AUC misranks**: PromptGuard has the best prior AUC but InjecGuard beats it at 1% FPR; off-the-shelf PI classifiers **collapse at low FPR** (ProtectAI v2 → 0% TPR @0.1% FPR). This is the core "why low-FPR reporting matters" evidence — and it's about the *exact* models in our harness.

**DataSentinel (arXiv:2504.11358, IEEE S&P 2025 Distinguished Paper):** detection framed as binary contaminated/clean with **FPR + FNR** as the primary metrics (not AUC). Prior known-answer detection: FPR ≤ 0.1, FNR ≤ 0.21 (optimization attacks); DataSentinel: FPR ≈ 0, FNR ≤ 0.07. PromptGuard: FNR 0 but **FPR up to 1.00** (flags everything).

**Critical Evaluation of PI Defenses (arXiv:2505.18333):** "AUC is insufficient for quantifying detection performance" — report FPR+FNR at the operating point. PromptGuard AUC 0.92 / FPR 0.89; Attention-Tracker AUC **1.00** but FNR **0.69** (misses 69% of attacks).

**Meta Prompt-Guard model card (v1):** in-dist Injections TPR 99.5% / FPR 0.8%; OOD CyberSecEval indirect injections **TPR 71.4%**; **3–5% FPR out-of-the-box**; explicitly warns in-distribution numbers don't reflect real OOD use.

## 3. Known detector caveats to anticipate in our results
- **Over-defense / high FP on benign instruction-like text** — ProtectAI deberta-v3-v2, PromptGuard. Expect high FPR on benign ham that contains instructions. (DataSentinel Table 3: PromptGuard FPR up to 1.00.)
- **Out-of-distribution collapse** — PI classifiers trained on prompt-injection text degrade on phishing / MIME-structured / obfuscated email (Meta model card; OOD indirect 71.4%). Directly threatens transfer to our `.eml` surfaces.
- **Indirect-injection is hardest** — "When Benchmarks Lie" (arXiv:2602.14161): PromptGuard 2 = 37.3%, LlamaGuard = 27.4% on indirect injection. ⚠️ *Caveats: its LLM judge is Llama-3.1-8B (7.1%) — do NOT transfer that floor to our **Claude** judge; and low guardrail scores partly reflect "architecturally cannot process tool injection," not pure misses.*

## 4. Validity-threats checklist (audit before freezing results 2026-07-03)
- [ ] **Threshold provenance** — was 0.35 chosen on the test set? If so, move calibration to a **validation split** (PromptShield's exact retrospective error). *Open: confirm how 0.35 was set.*
- [ ] **Dedup before split** — near-duplicate `.eml` across any train/eval boundary (we already dedup the corpus; confirm no benchmark email near-duplicates a benchmarked detector's training data).
- [ ] **Real-vs-synthetic leakage / shortcuts** — report real and synthetic results separately (already the plan); check a detector isn't keying on a synthetic artifact.
- [ ] **Class imbalance** — don't let it inflate the headline (this is *why* ROC-AUC must not lead); state the benign:malicious base rate.
- [ ] **Small-n slices** — bootstrap CIs on per-surface / per-threat_type cells; suppress or flag cells below ~30.
- [ ] **Score calibration** — don't compare heterogeneous detectors at one shared 0.35 threshold.

## 5. Framing note (related-work)
**AgentDojo / InjecAgent report attack-success-rate + task-utility for an end-to-end *agent* under attack**; our harness evaluates a standalone **detection classifier**, so **detection metrics (TPR@FPR, PR-AUC, FPR/FNR) are the correct framing** and those agent benchmarks are complementary (system-level), not directly comparable. *(Asserted from scope, not a verified source — confirm wording before citing.)*

## 6. Concrete changes this implies for `grade.py` (proposed, for the owner)
1. Add **`tpr_at_fpr(scores, labels, fpr_targets=[0.01, 0.005, 0.001])`** and make it the headline column.
2. Take a **`--val-manifest`** to calibrate any reported threshold; stop hard-coding 0.35 as the headline (keep it only as an illustrative operating point).
3. Emit **ROC and PR curve points** (for the paper's figures) per detector.
4. Add **bootstrap CIs** (e.g., 1,000 resamples) to `compute_metrics`, especially in `slice_by`.
5. Keep p50/p95 latency (already present) as a secondary system-cost column.

## Sources (verified primary unless noted)
- PromptShield — https://arxiv.org/abs/2501.15145 (TPR@FPR protocol + Table 4 numbers; threshold-on-test retrospective)
- Critical Evaluation of PI Defenses — https://arxiv.org/abs/2505.18333 ("AUC insufficient"; FPR/FNR)
- DataSentinel (IEEE S&P 2025) — https://arxiv.org/abs/2504.11358 (FPR/FNR as detection metrics)
- Meta Prompt-Guard model card — https://github.com/meta-llama/PurpleLlama/blob/main/Prompt-Guard/MODEL_CARD.md (OOD degradation)
- "When Benchmarks Lie" — https://arxiv.org/abs/2602.14161 (indirect-injection failure; cite with caveats)
- Imbalanced-metrics study (lower-tier, tabular — medium confidence) — https://www.mdpi.com/2227-7080/14/1/54 (MCC/F2/PR-AUC/H-measure; do **not** import F2-as-lead)

**Refuted / excluded** (failed 2/3 verification — phenomena hold, specific numbers don't): ROC-AUC "ceiling effect <3% positives" framing; "~60% accuracy on trigger words" (arXiv:2410.22770); "8.4-pt same-source AUC inflation" + "28% shortcut features" (arXiv:2602.14161).

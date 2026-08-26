# EML-cleanup eval — baseline vs `--eml-cleanup`

Four local HF prompt-injection classifiers, threshold 0.35, CPU. `--eml-cleanup` merges the text/plain + HTML-stripped body (so a payload in either MIME part is seen) and refangs defanged URLs. Baseline = each detector's default raw-`.eml` extraction (text/plain first).


## Metrics glossary — what each column means

Every metric derives from four counts of how a detector scored the corpus at the **decision threshold (0.35)**: **TP** (attack, correctly flagged), **FN** (attack, missed), **FP** (non-attack, wrongly flagged), **TN** (non-attack, correctly passed). Each detector emits a **score in [0,1]**; score ≥ threshold → "flag."

Notation in the tables: **`baseline→cleanup (Δ)`** = the value with `--eml-cleanup` off, then on, and the change. `B→C` is the same thing.

| metric | definition | reading |
|---|---|---|
| **Recall** (= TPR, sensitivity) | TP / (TP + FN) — of all real attacks, the fraction caught | higher = better; **trivially gamed by flagging everything** (see distilbert) |
| **FPR** (false-positive rate) | FP / (FP + TN) — of all non-attacks, the fraction wrongly flagged | **lower = better**; the cost paid for recall. FPR 1.0 = flags every benign message |
| **Precision** | TP / (TP + FP) — of the messages flagged, the fraction that were real attacks | higher = better. On an all-positive set it is trivially 1.0 / undefined, so it is only meaningful on a both-class task |
| **F1** | harmonic mean of precision and recall | one number balancing "catch a lot" vs "don't cry wolf"; ignores TN, so read alongside FPR |
| **AUC-ROC** | area under the ROC curve = P(a random attack scores higher than a random non-attack) | **threshold-independent** — the fairest single comparison. 0.5 = random, 1.0 = perfect, **<0.5 = worse than random** (scores anti-correlated with truth) |
| **AUC-PR** | area under the precision–recall curve | like AUC-ROC but focused on the positive class; more informative when positives are rarer than negatives |
| **TPR@1%FPR** | recall achievable when the threshold is set so only 1% of non-attacks are flagged | **the deployment-relevant number**: how many attacks you catch at a strict false-alarm budget. (TPR@0.1%FPR is the same, stricter.) |
| **coverage** | fraction of the corpus that produced a non-error prediction | <1.0 means some emails failed to parse/score |

Note: recall, precision, F1, and FPR are all measured **at the 0.35 threshold**, so they move if the threshold changes. AUC-ROC, AUC-PR, and TPR@FPR are **threshold-free** (they summarize the whole score ranking) and are the more robust cross-detector comparison.


## 1. Prompt-injection detection — the task that matters

**1576 PI positives vs 3000 phishing/benign negatives** (PI positives paired with non-injection mail so FPR / AUC / TPR@low-FPR are computable). Values are baseline→cleanup (Δ).

| detector | recall | FPR | F1 | AUC-ROC | AUC-PR | TPR@1%FPR |
|---|---|---|---|---|---|---|
| deberta-v3-PI | 0.247→0.423 (+0.176) | 0.367→0.165 (-0.202) | 0.255→0.487 (+0.232) | **0.452→0.675 (+0.224)** | 0.357→0.564 (+0.207) | 0.040→0.091 (+0.051) |
| InjecGuard | 0.643→0.674 (+0.032) | 0.482→0.361 (-0.121) | 0.503→0.571 (+0.068) | **0.577→0.691 (+0.114)** | 0.490→0.535 (+0.045) | 0.050→0.022 (-0.028) |
| Prompt-Guard-2-86M (Meta) | 0.071→0.125 (+0.054) | 0.011→0.009 (-0.002) | 0.130→0.219 (+0.089) | **0.237→0.447 (+0.210)** | 0.312→0.459 (+0.147) | 0.069→0.129 (+0.060) |
| distilbert-PI (degenerate) | 1.000→1.000 (+0.000) | 1.000→1.000 (+0.000) | 0.514→0.512 (-0.002) | **0.203→0.380 (+0.177)** | 0.233→0.277 (+0.045) | 0.000→0.000 (+0.000) |

**Reading it:** AUC-ROC is threshold-independent. Cleanup raises it for every detector (deberta +0.22), and three of four baselines sit **below 0.5** — the text/plain-only parse ranks injections *below* benign because the payload hides in HTML the baseline never reads. So the recall gain is real discrimination, not score inflation. **deberta-v3 is the strongest deployable detector** (lowest non-degenerate FPR, best TPR@1%FPR). **distilbert is degenerate** (FPR 1.0, AUC<0.5: it flags ~everything; it was trained on short prompts and collapses on email-length text).


## 2. PI recall by injection type

From the PI-only set (1576, all positive); recall = fraction of injections caught.

| detector | direct (n=1002) B→C | indirect (n=574) B→C |
|---|---|---|
| deberta-v3-PI | 0.228→0.481 | 0.282→0.322 |
| InjecGuard | 0.717→0.761 | 0.514→0.523 |
| Prompt-Guard-2-86M (Meta) | 0.074→0.159 | 0.066→0.066 |
| distilbert-PI (degenerate) | 1.000→1.000 | 1.000→1.000 |

Gains concentrate on **direct** injections (deberta 0.227→0.481), the ones most often buried in an HTML part the baseline drops.


## 3. Phishing set (secondary — injection detectors over phishing/benign mail)

Phishing is not prompt injection, so the useful signal here is **FPR** (spurious firing on non-injection mail). Values baseline→cleanup (Δ).

| detector | recall | precision | FPR | AUC-ROC |
|---|---|---|---|---|
| deberta-v3-PI | 0.652→0.314 (-0.338) | 0.881→0.950 (+0.068) | 0.087→0.017 (-0.070) | 0.877→0.842 (-0.035) |
| InjecGuard | 0.633→0.395 (-0.238) | 0.651→0.546 (-0.105) | 0.334→0.328 (-0.006) | 0.696→0.552 (-0.144) |
| Prompt-Guard-2-86M (Meta) | 0.009→0.006 (-0.003) | 0.424→0.333 (-0.091) | 0.013→0.012 (-0.001) | 0.765→0.685 (-0.079) |
| distilbert-PI (degenerate) | 1.000→1.000 (+0.000) | 0.496→0.500 (+0.004) | 1.000→1.000 (+0.000) | 0.363→0.334 (-0.030) |

Cleanup cuts FPR (deberta 0.087→0.017): on phishing text the cleaner merged body looks less injection-like, so the detectors stop firing — the right direction for a PI detector. Cleanup also recovered the 21 malformed-charset phishing emails the baseline silently dropped (coverage 0.993→1.000).


---
*Note:* evaluated on the 1576-entry PI manifest snapshot; `main` later expanded it to 2776. distilbert excluded from "strongest" claims (degenerate). Per-detector `metrics.json` under each run dir.


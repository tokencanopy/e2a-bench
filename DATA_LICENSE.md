# Data licensing and attribution

The **code** in this repository (`eval/`, `dataset/*/scripts/`) is Apache-2.0 (see
[`LICENSE`](LICENSE)). The **data** under `dataset/` mixes sources with their own terms.
The authoritative per-source table, including fetch scripts and redistribution decisions,
is [`dataset/sources/NOTES.md`](dataset/sources/NOTES.md). Summary:

| Source | Used as | License | Redistributed here? |
|---|---|---|---|
| Nazario phishing corpus | real phishing `.eml` | CC-BY-4.0 | yes, with attribution |
| SpamAssassin public corpus | benign ham + spam `.eml` | Apache SpamAssassin corpus terms (freely redistributable) | yes |
| InjecAgent | injection payload templates | MIT | yes (re-rendered as `.eml`) |
| AgentDojo | email carriers + injection goals | MIT | yes (re-rendered as `.eml`) |
| LLMail-Inject | injection payloads | MIT | yes (re-rendered as `.eml`) |
| NotInject | benign over-defense probes | MIT | yes (re-rendered as `.eml`) |
| CyberSecEval3 visual prompt injection | image-PI test set | MIT, dataset card: evaluation only | **no** — `dataset/prompt-injection/image-pi-email/build.py` re-downloads it |
| Enron / CEAS08 / Ling / Nazario-5 (Zenodo repackagings) | optional OOD phishing splits | varies, not all redistribution-cleared | **no** — only the fetch/build scripts ship (`dataset/ingest_zenodo.py`, `eval/build_phishing_external_splits.py`); the paper's tables do not use these splits |
| Handcrafted / synthetic material (adaptive supplement, synthetic lures, matched benign controls, real-incident reproductions) | PI positives, controls | this repository's license | yes |

Attribution details for the phishing corpus are in
[`dataset/phishing/ATTRIBUTION.md`](dataset/phishing/ATTRIBUTION.md).

URL handling differs by provenance. **Synthetic** material authored for this benchmark is
stored defanged (`hxxp://`, `[.]`) and re-fanged only in memory at evaluation time. The
**public corpora** (Nazario, SpamAssassin) are redistributed byte-for-byte as published
upstream — headers, recipient addresses, and URLs intact — because the corpus bytes are the
benchmark: altering them would change detector inputs and invalidate the committed results.
The URLs are decades-old phishing infrastructure, long dead, and these corpora have been
publicly distributed in this form by their maintainers and countless papers. Do not resolve
or click them. The corpus is released for defense research; the attack content reproduces
already-public techniques and CVEs.

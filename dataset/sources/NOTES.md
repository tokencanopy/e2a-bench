# Reused-payload provenance & license tracking

⚠️ **Verify each source's license before committing any redistributed payloads here.**
If a license forbids redistribution, store only a generator/reference that
re-derives the payloads, not the payloads themselves.

**Phase 1 — phishing/benign (in use now):**
| source | url | what we took | license | redistribute? | notes |
|--------|-----|--------------|---------|---------------|-------|
| Nazario phishing corpus | https://monkey.org/~jose/phishing/ | real phishing `.eml` (phishing class) | **CC-BY-4.0** | yes (attribution) | fetched via `scripts/fetch_corpora.sh`; ~5k → ~3.1k after dedup |
| SpamAssassin public corpus | https://spamassassin.apache.org/old/publiccorpus/ | **ham→benign** + **spam→scam** `.eml` | free / redistributable | yes | fetched; one corpus supplies both benign and scam |
| Enron | (optional, **not yet used**) | benign `.eml` (diversify) | varies — verify | TBD | candidate to modernize the benign split |

**Phase 2 — prompt injection (payloads, not yet ingested):**
| source | url | what we'd take | license | redistribute? | notes |
|--------|-----|--------------|---------|---------------|-------|
| LLMail-Inject | https://arxiv.org/abs/2506.09956 · https://huggingface.co/datasets/microsoft/llmail-inject-challenge | injection payloads (subject+body, plaintext) | **MIT** | yes | optional deterministic sample via `prompt-injection/scripts/fetch_payloads.py --include-llmail`; re-render across e2a surfaces; original ASR labels are metadata, not detector labels |
| InjecAgent | https://arxiv.org/abs/2403.02691 | attacker-goal templates (exfil-via-send-email) | **MIT** | yes | tool-response injection; re-render into `.eml` |
| AgentDojo | https://arxiv.org/abs/2406.13352 · https://github.com/ethz-spylab/agentdojo | workspace inbox email carriers + email/inbox injection goals | **MIT** | yes | 30 base email scenarios via `fetch_agentdojo_email.py`, expanded across six AgentDojo attack families via `expand_agentdojo_attacks.py`; preserves base scenario, user task, injection task, and formulation metadata before e2a `.eml` rendering |
| Adaptive complex PI supplement | hand-authored in this repository | six multi-stage attack scenarios across three combined MIME structures | project dataset license | yes | synthetic robustness slice; labeled `source=handcrafted`, `split=adaptive`; must be reported separately from AgentDojo and other public-source payloads |
| NotInject | https://arxiv.org/abs/2410.22770 · https://huggingface.co/datasets/leolee99/NotInject | 339 benign over-defense probes (text containing injection trigger words in legitimate context) | **MIT** | yes (attribution) | fetched + wrapped as plaintext `.eml` via `notinject/scripts/fetch_notinject.py`; 113 samples x 3 trigger-count subsets; used as benign negatives to measure over-defense, never as PI positives |
| EchoLeak / Gemini / Mimecast | writeups (arXiv:2509.10540 / bleepingcomputer / immersivelabs) | reproduction recipes | n/a | yes (ours) | structural-vector reproductions (markdown-exfil / CSS-hidden / URL-fragment) |

**Phase 3 — image prompt injection in email (`prompt-injection/image-pi-email/`):**
Built by `image-pi-email/build.py`; all positives/negatives wrapped as the `image_attachment` email surface. Per-record provenance is in the manifest (`provenance.source`, `base_payload_id`).
| source | url | what we took | license | redistribute? | notes |
|--------|-----|--------------|---------|---------------|-------|
| CyberSecEval3 Visual Prompt Injection | https://huggingface.co/datasets/facebook/cyberseceval3-visual-prompt-injection · https://github.com/meta-llama/PurpleLlama | 1,000 visual-PI PNGs (instruction rendered into the image) | **MIT — but dataset card states "evaluation purposes only, do not train"** | **NO — reference only** | NOT committed; `build.py` re-downloads via `huggingface_hub` into the gitignored `cache/`. Use as a held-out **test** set only. `image_text` field = ground-truth in-image text. |
| Our PI corpus, PDF surface (rasterized) | this repo `prompt-injection/eml/*_pdf_attachment.eml` (→ injecagent / agentdojo / llmail-inject upstream) | the `application/pdf` part of each pdf_attachment case, rasterized to a page image (`pdftoppm` @150dpi) | inherits upstream (**MIT**) | yes (ours, re-rendered) | cross-modal twin of the text/PDF surfaces, linked via `base_payload_id` (`pi_XXXX`) |
| Benign controls (rendered) | this repo `prompt-injection/benign/` | benign email bodies rendered to a document-style image | project dataset license | yes | FPR negatives (CyberSecEval3 ships no benigns) |

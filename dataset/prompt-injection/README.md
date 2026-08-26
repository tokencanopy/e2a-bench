# Prompt-injection family (Phase 2)

> **✅ Ready for test: 2776 `.eml`** — 1002 direct + 1774 indirect
> (`eml/`), from 347 payloads × 8 surfaces. Benign negatives are shared
> from `../phishing/` (ham), `../notinject/`, and the 200 structurally
> matched controls in `benign/`.

Current distributions and evaluation accounting are generated in
[`STATS.md`](STATS.md).

The other half of the benchmark (see `../phishing/` for Phase 1). Here the malice
is **instruction text that hijacks the agent** — *not* a malicious URL. Labels:
`threat_type ∈ {prompt_injection_direct, prompt_injection_indirect}`, `is_malicious=true`,
`injection_technique=…`. Negatives reuse the same benign/ham split as phishing.

> **Status: scaffold built.** Phase 1 (phishing) stands up the shared
> detect→score→metrics harness; PI plugs into it through generated `.eml`
> messages and `manifest.jsonl`.

## Direct vs indirect
- **Direct** — the injection is in content the agent is told to act on (e.g. the email body it's asked to summarize/reply to).
- **Indirect** — the injection rides in third-party/retrieved content the agent ingests as data (quoted threads, forwarded mail, an attachment, tool output) and was not authored by the user.

## Sources (by provenance)
Unlike phishing (real `.eml` corpora), PI sources are **injection payloads (text)** we
**re-render into `.eml`** across surfaces — that rendering is the contribution.
1. **Public corpora (payloads)** — all MIT, reusable:
   - **LLMail-Inject** (https://huggingface.co/datasets/microsoft/llmail-inject-challenge) — subject+body plaintext injections (sample + dedupe). We reuse the attack text as payloads; we do **not** reuse its original tool-call ASR labels as detector labels.
   - **InjecAgent** (https://github.com/uiuc-kang-lab/InjecAgent) — attacker-goal/instruction templates (exfil-via-send-email).
   - **AgentDojo** (https://github.com/ethz-spylab/agentdojo) — workspace/email scenarios: real inbox email carriers plus workspace injection goals. We keep the task context as metadata and re-render into e2a `.eml`; we do **not** run the original AgentDojo agent benchmark here.
2. **Synthetic** — generate + structurally render payloads (shared with phishing's transform).
3. **Benign** — reuse `../phishing/` ham (SpamAssassin). No separate benign source.

See `../sources/NOTES.md` (Phase-2 table) for licenses/provenance.

## Structural rendering (the contribution — shared with phishing)
PI corpora are **plaintext / tool-context**, so they don't exercise email structure.
We re-render each payload into a real MIME `.eml` across the 8 surfaces
(plaintext / visible-HTML / CSS-hidden / multipart-mismatch / subject-header /
quoted-thread / PDF-attachment / encoded) — same machinery as
`../phishing/scripts/` (`build_manifest.py` + the structural transform). "Same
payload, different packaging → different detection rate" is the finding.

## Schema, ingestion, grading (shared)
- **Schema:** reuse the shared family-agnostic `EmailRecord` at `../schema/email_record.schema.json` (`threat_type=prompt_injection_*`, `injection_technique` incl. `raw`).
- **Ingestion:** identical to phishing — e2a is SMTP-only; eval parses `.eml` directly via `mailparse.ParsedBody`; `auth` is assigned per `sender_auth_condition`, not parsed.
- **Grading:** detection accuracy (precision/recall/ROC-AUC), sliced by `threat_type`/`surface` — NOT agent tool-call ASR.

## Current state (Phase 2 — in progress)
- **`payloads.jsonl`** — ✅ currently **347 prompt-injection payload rows**:
  62 real **InjecAgent** instructions, 5 canonical phrasing-technique seeds,
  100 **LLMail-Inject** subject/body attacks, and 180 AgentDojo payloads
  expanded from 30 base workspace/email scenarios.
- **LLMail-Inject ingestion** — ✅ implemented as an optional deterministic sample:
  `python3 scripts/fetch_payloads.py --include-llmail --llmail-max 100`.
  This appends LLMail subject/body attacks as `source=llmail-inject` payloads with
  original `RowKey`, `scenario`, `objectives`, and outcome metadata preserved.
- **AgentDojo email ingestion** — ✅ implemented as scenario-level adaptation:
  `python3 scripts/fetch_agentdojo_email.py --append --max-scenarios 30`.
  This extracts only workspace inbox emails with `email_*_injection` placeholders
  and combines them with workspace email/inbox injection goals. Each row preserves
  `user_task`, `injection_task_id`, carrier email metadata, and source file in
  `source_metadata`.
- **AgentDojo attack expansion** — ✅
  `python3 scripts/expand_agentdojo_attacks.py` expands each of the 30 base
  scenarios across six deterministic AgentDojo attack families:
  `direct`, `ignore_previous`, `system_message`, `injecagent`,
  `important_instructions`, and `tool_knowledge`. This produces 180 payloads.
  The `tool_knowledge` wording is adapted for email-native detector evaluation;
  this project does not execute AgentDojo's original tool runtime.
- **`render_pi.py`** — ✅ embeds each row into an email across the 8 surfaces →
  `eml/` + `manifest.jsonl`. Existing build: **2776 `.eml`** (347 × 8):
  **1002 direct** + **1774 indirect**. The AgentDojo subset is exactly
  **1440 `.eml`** (30 base scenarios × 6 attack formulations × 8 surfaces).
  AgentDojo rows are always labeled `prompt_injection_indirect` because the
  malicious instruction is untrusted external email content.
- **Visual supplement** — ✅ small optional slice in `visual-supplement/`:
  4 synthetic injection instructions rendered as embedded image and PNG
  attachment (**8 `.eml`**). This is reported separately from the main build.
- **Benign controls** — ✅ `benign/` contains 25 benign seeds rendered across
  the same 8 surfaces (**200 `.eml`**). These cases test false positives on
  complex MIME structure and benign uses of attack-like words such as
  `ignore`, `SYSTEM`, `TODO`, and `send_email`.
- **Adaptive complex supplement** — ✅ `adaptive-supplement/` contains
  6 hand-authored multi-stage attacks rendered across 3 combined structural
  variants (**18 `.eml`**). These test conditional behavior, delayed triggers,
  data-dependent tool chains, authority laundering, and instructions split
  across MIME locations. Report this slice separately from AgentDojo.
- **GCG-style suffix supplement** — ✅ `gcg-supplement/` contains
  13 synthetic adversarial-suffix seeds and 10 benign hard-negative seeds
  rendered across 4 email surfaces (**92 `.eml`**), plus 8 real
  JailbreakBench GCG challenge emails in `gcg-supplement/real/`, plus a
  reproducible HuggingFace real-GCG subset in `gcg-supplement/hf-gcg/`
  filtered to evaluated rows with `strongreject_finetuned >= 0.5`. The synthetic
  slice tests high-entropy punctuation/noise after otherwise natural email text;
  the real challenge slices test optimized mixed alpha/symbol suffixes and
  should be reported separately when evaluating GCG robustness.

Recommended build:
```bash
cd dataset/prompt-injection
python3 scripts/fetch_payloads.py --include-llmail --llmail-max 100
python3 scripts/fetch_agentdojo_email.py --append --max-scenarios 30
python3 scripts/expand_agentdojo_attacks.py
python3 scripts/render_pi.py
python3 benign/render_benign.py
python3 adaptive-supplement/render_adaptive.py
python3 gcg-supplement/render_gcg.py
python3 gcg-supplement/real/render_real_gcg.py
python3 gcg-supplement/hf-gcg/fetch_hf_gcg.py --limit 10000
python3 gcg-supplement/hf-gcg/render_hf_gcg.py
python3 ../../eval/combine_manifests.py --base-dir ../..
python3 scripts/build_stats.py
```

Dataset accounting:
```text
30 AgentDojo base scenarios
× 6 attack formulations
× 8 structural surfaces
= 1440 rendered AgentDojo email instances
```

These are 1440 rendered instances, not 1440 independent tasks. For training or
validation splits, group by `provenance.base_scenario_id` so variants of one
base scenario cannot leak across splits.

Interpretation: **LLMail-Inject = payload source; e2a prompt-injection dataset =
email-native detector evaluation.** LLMail's original benchmark evaluates agent
tool-call compromise; this dataset evaluates gateway malicious-email detection.

**AgentDojo = task-contextual email scenario source; e2a prompt-injection dataset =
email-native detector evaluation.** AgentDojo's original benchmark evaluates
agent task utility and attack success; this dataset evaluates whether the inbound
email should be detected before agent execution.

## Layout
```
dataset/prompt-injection/
├── README.md       # this file
├── STATS.md        # auto-generated current data card ✅
├── payloads.jsonl  # curated injection payload/scenario rows ✅
├── agentdojo_email_scenarios.jsonl  # AgentDojo workspace/email intermediate ✅
├── eml/            # rendered .eml (payload/scenario rows × 8 surfaces) ✅
├── manifest.jsonl  # EmailRecords for the rendered .eml ✅
├── benign/         # 200 structurally matched benign controls ✅
├── adaptive-supplement/ # 18 complex adaptive PI cases ✅
├── gcg-supplement/ # synthetic + real GCG suffix supplements ✅
├── visual-supplement/ # image prompt-injection supplement ✅
└── scripts/        # fetch, expand, and render stages ✅
```

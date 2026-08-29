# Dataset Collection — email-agent malicious-email detection benchmark

Build-ready plan for the benchmark behind the paper. The defense is a
**gateway detector** that emits a **confidence score**; eval is **detection
accuracy** (precision/recall/AUC) vs. a naïve PI-detector (lower bound) and
SOTA models (upper bound) — **not** agent tool-call ASR.

**One test case = one `.eml` file** (the exact bytes e2a receives inbound) +
one annotation record (`schema/email_record.schema.json`).

## ✅ Ready for test (as of 2026-06-24)
| Family | Class | Count | Location |
|---|---|---|---|
| Phishing | **benign** (ham) | 1,500 | `phishing/corpus/` (`ham_*`) |
| Phishing | **phishing** — real | 1,500 | `phishing/corpus/` (`nazario_*`, `sa_spam_*`) |
| Phishing | **phishing** — synthetic | 200 | `phishing/synthetic/eml/` |
| Prompt injection | **direct** | 1,002 | `prompt-injection/eml/` |
| Prompt injection | **indirect** | 1,774 | `prompt-injection/eml/` |
| Prompt injection | **adaptive complex** | 18 | `prompt-injection/adaptive-supplement/eml/` |
| Prompt injection | **benign matched controls** | 200 | `prompt-injection/benign/eml/` |

The prompt-injection combined evaluation additionally includes 1,500 real ham
and 339 NotInject over-defense controls. Run `eval/combine_manifests.py` to
materialize the current PI evaluation manifest.
- **Labels:** `threat_type ∈ {benign, phishing, prompt_injection_direct, prompt_injection_indirect}`. Phishing carries content **`category`** (credential / financial / advance_fee / lottery_prize / gift_card / delivery / other); PI carries **`injection_technique`** + direct/indirect.
- **Eval:** detection accuracy (precision / recall / ROC-AUC), sliced by `threat_type` / `category` / `surface`. The 1,500 **benign** are the shared FPR negatives.
- **Held-out:** 4,595 deduped phishing-family emails (not sampled) for scale/robustness.

## Repository structure
```
dataset/
├── schema/email_record.schema.json   # shared EmailRecord schema (both families)
├── sources/NOTES.md                  # provenance + licenses
├── phishing/                         # Phase 1 — READY
│   ├── manifest.jsonl                #   3,000 real records
│   ├── corpus/                       #   3,000 curated .eml (benign + phishing)
│   ├── synthetic/                    #   lures.jsonl + eml/ (200) + manifest
│   ├── scripts/                      #   fetch_corpora / parse_eml / dedup / build_manifest / gen_lures / render_surfaces
│   ├── STATS.md  README.md  ATTRIBUTION.md
│   └── (ham/ real/ _raw/  → transient, gitignored, via fetch_corpora.sh)
└── prompt-injection/                 # Phase 2 — READY
    ├── payloads.jsonl                #   347 injection payloads
    ├── eml/                          #   2,776 malicious .eml
    ├── adaptive-supplement/          #   18 complex adaptive .eml
    ├── benign/                       #   200 matched benign .eml
    ├── manifest.jsonl
    └── scripts/                      #   fetch_payloads / render_pi
```

## Two threat families (both in scope)
The detector flags malicious email before the agent acts. "Malicious" spans:
1. **Prompt injection** — direct + indirect; text that hijacks the agent's instructions (source: LLMail-Inject, InjecAgent, AgentDojo, synthetic).
2. **Phishing** (`threat_type=phishing`, binary; content type in `label.category`) — socially-engineered lures (credential, financial, advance-fee/419, lottery, gift-card, delivery). **The email contains NO injection prompt** — the malicious signal is the **URL itself** (recorded in `label.malicious_urls`) or the lure intent. *(The old source-based phishing/scam split was collapsed — see [`phishing/README.md`](phishing/README.md).)*

> **Scope (resolved 2026-06-19): PI + phishing — both in scope.** They are different detection problems: prompt injection is malicious *instruction text*; phishing is a malicious *URL/lure* with no injection. So the detector needs two signals (an injection-text classifier and a URL/phishing detector — or one model trained on both), baselines differ per family, and detection is **reported separately per `threat_type`** (a detector strong on injection may be weak on phishing).

## Build order — start with phishing
Build the **phishing family first**, prompt injection second:
1. **Phase 1 — Phishing/scam.** Sources by **provenance** (full analysis + verdicts in [`phishing/README.md`](phishing/README.md)): **public corpora** (Nazario→phishing; SpamAssassin→spam *and* ham) and **synthetic** lures. Benign is a *label/role*, not a separate source — it comes from the public corpora's SpamAssassin **ham**. Caveat from the corpora fetch: most public phishing aggregates are **body-text-only / dated** — full-`.eml` ham is easy (SpamAssassin), but modern full-`.eml` phishing is scarce, so it comes from Nazario's recent mailboxes + synthetic. Curate + label (`is_malicious` + `malicious_urls`), assign `sender_auth_condition`. The **fastest path to a first end-to-end detection number** + a working eval harness.
2. **Phase 2 — Prompt injection.** Reuse payloads (LLMail-Inject / InjecAgent / AgentDojo) and run them through the structural-rendering layer (below) to add HTML/hidden/PDF surfaces. This is the synthesis-heavy part; it plugs into the same harness Phase 1 already stood up.

Rationale: phishing data exists as real `.eml` (no generation), it's the sync's *primary* scenario, and it unblocks the detector + eval end-to-end early.

## How a `.eml` gets into e2a (verified against the OSS code)
e2a's **only** inbound is **SMTP** — `relay.Data(io.Reader)` → `deliverMessages(senderEmail, body []byte)`. There is **no HTTP/file endpoint that ingests a `.eml`**. So a `.eml` enters two ways:
- **Live demo:** SMTP the `.eml` to the relay (`swaks --server host:25 --data file.eml`, or Python `smtplib`). e2a stores the bytes as `raw_message` and parses them.
- **Eval (no relay needed):** parse the `.eml` bytes directly with e2a's own parser — `mailparse.ParsedBody(raw []byte, maxBytes int)` (internally `mail.ReadMessage(bytes.NewReader(raw))`) — or Python `email`, to produce `parsed_text`/body. Use this for large-scale detection eval.

Either way the detector consumes a `MessageView`; `detector_input` mirrors it 1:1: `from`, `to/cc/reply_to`, `subject`, `body{text,html}`, `parsed_text`, `auth{spf,dkim,dmarc → {status,detail}}`, `raw_message`. The detector's verdict maps onto e2a's existing `flagged` / `flag_reason` / `labels` fields.

- **Attachments are NOT a structured inbound field** — they live inside `raw_message`. PDF-attachment attacks are detected by parsing `raw_message` (we cache a `text_extract` in `detector_input.attachments`).
- **`auth` is ASSIGNED, not copied from the `.eml`.** e2a **recomputes** SPF/DKIM/DMARC live from the SMTP envelope + connecting IP + DNS + DKIM signature, and **ignores** the `.eml`'s embedded `Authentication-Results` header. A replayed capture's embedded `dmarc=pass` will **not** reproduce that verdict. So we **set** `sender_auth_condition` (`verified`/`unauthenticated`/`spoofed`) per test case — never read it from the file.
- **`auth` is a feature, never a label.** The corpus deliberately mixes authenticated-malicious and unauthenticated-benign cases (real phishing sent from fully authenticated infrastructure passes all three) — a detector keying on auth alone must fail.

## Reuse existing datasets → our schema (ingestion mapping)
| Source | Format (verified) | Maps to |
|--------|-------------------|---------|
| **LLMail-Inject** (HF `microsoft/llmail-inject-challenge`) | columns: `subject`, `body` (plaintext), `objectives` (13), `scenario` (40), `outcomes{email.retrieved, defense.undetected, exfil.*}`, `RowKey` | `subject`→subject, `body`→body.text, `objectives`→`threat_type=prompt_injection_*`, `RowKey`→`provenance.source_id`. **Plaintext only** → re-render through our structural transform to add HTML/PDF/hidden surfaces. |
| **InjecAgent** | `user_cases`: `User Tool / User Instruction / Tool Response Template` (carries `<Attacker Instruction>` placeholder); `attacker_cases_ds`: `Attacker Tools[] / Attacker Instruction / Expected Achievements / Attack Type` | `Attacker Instruction`→injected payload rendered into an `.eml`; `threat_type=prompt_injection_indirect`; `Attack Type`→`scenario`. |
| **AgentDojo** | task suites: workspace user_task + injection_task + inbox email carriers with injection placeholders | workspace email carrier + injection_task→scenario-level payload; `user_task`/`injection_task` retained in `source_metadata`; `threat_type=prompt_injection_indirect`. |
| **Phishing corpora** (e.g. Nazario) | real `.eml` | `threat_type=phishing/scam`, `surface=[html_body,hyperlink]`. |
| **Ham (benign)** — SpamAssassin ham (used); Enron optional, not yet used | real `.eml` | benign split (the hard FPR cases: HTML newsletters, threads). |

**Design principle:** reuse vetted *payloads*; contribute our *structural rendering* (below). Novelty is the packaging + the email-native eval, not a new detector.

## Our structural rendering layer (the contribution)
Hold a payload constant, vary only the email structure → "same words, different
packaging → different detection rate." One payload → real MIME embedding it ~8 ways
(these populate `surface[]`):

1. plaintext body (baseline)  2. visible HTML  3. CSS-hidden HTML (`font-size:0`/`color:#fff`/off-screen)
4. multipart mismatch (benign `text/plain` + malicious `text/html`)  5. subject/header
6. quoted-reply / thread burial  7. PDF attachment (text layer)  8. encoding/obfuscation (quoted-printable, base64, zero-width, URL fragmentation)

Plus a sender-auth condition per email: `verified` | `unauthenticated` | `spoofed`.

## Sizing (sprint / Track A)
- **~500–800 attack `.eml`s** — ~30–50 base payloads × 8 structural surfaces + scenario/auth variation.
- **~250 benign `.eml`s** (HTML newsletters, threads, PDFs) — the FPR set.
- **~20 real-incident reproductions** (EchoLeak/Gemini/Mimecast).
- **~50–150 adaptive** cases (built after seeing what the detector misses).

Rationale: AgentDojo shipped 629 security cases, InjecAgent 1,054 — ~500–1,000 is credible for a detection eval.

## Grading (automatic, detection-oriented)
Eval = `detector(detector_input) → confidence ∈ [0,1]`, thresholded against
`label.is_malicious` → precision / recall / ROC-AUC, sliced by `threat_type`
and `surface`. Baselines: naïve PI detector (lower) vs. SOTA (upper). Plus a
system-level throughput test (QPS/latency) per the sync. No human labels, no
agent-hijack ASR.

## Folder layout
```
dataset/
├── README.md                     # this file
├── corpus/                       # the .eml files (one per test case) — to be generated
├── manifest.jsonl                # one EmailRecord per line (schema/email_record.schema.json)
├── sources/NOTES.md              # reused-payload provenance + license tracking
├── schema/email_record.schema.json
└── generation/                   # pipeline (load → structural_transform → assemble → grade)
```

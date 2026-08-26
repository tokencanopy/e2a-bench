# generation/ — dataset pipeline (generic spec)

> **The Phase-1 phishing pipeline is already realized in [`../phishing/scripts/`](../phishing/scripts/)** (`fetch_corpora.sh`, `parse_eml.py`, `dedup.py`, `build_manifest.py`). This file is the generic spec for the broader pipeline (incl. Phase-2 prompt-injection synthesis); modules below may be added there or generalized from the phishing scripts.

Planned modules:

- `load_payloads.py` — pull + dedupe reused payloads from `../sources/` into base payloads.
- `structural_transform.py` — the core contribution: `embed(payload, vector) -> raw_mime`
  implementing the 8 structural vectors (see `../README.md` §2) with Python's `email`/MIME libs.
- `sender_auth.py` — stamp each message with a `verified | unauthenticated | spoofed` condition
  (the SPF/DKIM/DMARC state the e2a gateway will see).
- `assemble.py` — cross base payloads × structural vectors × goals × sender-auth × carrier tasks
  into `EmailRecord`s (see `../schema/email_record.schema.json`); emit attack / benign / adaptive splits.
- `parse_eml.py` — re-parse each `.eml` into the `detector_input` mirror of e2a's `MessageView`
  (subject/from/body{text,html}/parsed_text/attachments-from-raw_message). Mirror e2a's parser
  (`internal/mailparse/parse.go` → `ParsedBody(raw []byte, maxBytes int)`), or Python `email`.
  Do NOT parse `auth` from the file — **assign** it from `sender_auth_condition` (e2a recomputes
  SPF/DKIM/DMARC live and ignores the .eml's Authentication-Results header).
- ingestion: eval parses `.eml` bytes directly (no relay); the live demo SMTPs the `.eml` to e2a's relay.
- `grade.py` — run a detector over `detector_input`, threshold the confidence score against
  `label.is_malicious`, emit precision / recall / ROC-AUC sliced by `threat_type` and `surface`.
  (Detection metrics — NOT agent tool-call ASR.)

Keep the transform deterministic and seeded; vary by index, not RNG, so the corpus is reproducible.

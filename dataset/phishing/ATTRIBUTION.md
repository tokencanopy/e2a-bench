# Corpora attribution & licenses

## Nazario Phishing Corpus — CC-BY-4.0
Jose Nazario, "phishingcorpus" — https://monkey.org/~jose/phishing/
Licensed **CC-BY-4.0**: derivative works + commercial use permitted, **attribution required**.
Hand-classified; representative, not exhaustive (the author's personal inbox). Earlier
mailboxes were anonymized (destination IPs/domains); **later ones are NOT** — they contain
real addresses (**PII**). Contains real (mostly dead) phishing URLs; per the author, no
malicious executable attachments.

## SpamAssassin Public Corpus
https://spamassassin.apache.org/old/publiccorpus/ — freely redistributable (Apache project).
`easy_ham` + `hard_ham` → benign (ham); `spam` + `spam_2` → malicious (2002–2005, dated). Nazario contributes both 2005-era *and* **2020–2023** yearly mailboxes (modern phishing).

## Handling rules
- The **full upstream corpus is NOT committed** (size ~84 MB + PII). Run `scripts/fetch_corpora.sh` to materialize it under `ham/` and `real/` (both gitignored).
- Only the curated `corpus/` (3,000 `.eml`: 1,500 ham + 1,000 Nazario phishing + 500 SpamAssassin spam) + `manifest.jsonl` + the `scripts/` are committed.
- **Release decision:** the curated corpus is redistributed **byte-for-byte as published upstream** (headers, recipient addresses, and URLs intact) — the bytes are the benchmark, and altering them would invalidate the committed results. Synthetic material is defanged; see [`DATA_LICENSE.md`](../../DATA_LICENSE.md).
- Do **not** resolve or click the URLs.

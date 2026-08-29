# Phishing family (Phase 1)

> **✅ Ready for test: 3,200 `.eml`** — 1,500 benign + 1,500
> phishing-family malicious (`corpus/`: 1,000 Nazario phishing + 500
> SpamAssassin spam) + 200 synthetic (`synthetic/eml/`). 4,595 deduped held-out.
> Live counts in [`STATS.md`](STATS.md).

Detection of malicious email: the malice is a **malicious URL / lure**, **no
injection prompt**. Labels: **`threat_type ∈ {benign, phishing, spam}`**;
`phishing` and `spam` are both phishing-family positives for evaluation, while
remaining distinguishable in per-type slices,
`is_malicious`, **`category`** (content type: credential / financial / advance_fee /
lottery_prize / gift_card / delivery / other), `malicious_urls=[…]`. Negatives = benign (ham).

## Sources (by provenance)
Emails come from two **provenances**. The **benign vs malicious** split is a *label/role*, not a separate source — e.g. SpamAssassin (a public corpus) supplies *both* malicious spam *and* benign ham.

1. **Public corpora** — **Nazario → phishing (2005-era *and* 2020–2023 yearly mailboxes, so ~23% of sampled phishing is modern)**; **SpamAssassin → both spam (malicious) *and* ham (benign)** (2002–05, dated).
2. **Synthetic** ✅ implemented (`synthetic/`, 25 lures → 200 `.eml`) — LLM-written lures (gift-card / sign-in / credential) carrying a controlled malicious URL, **generate-then-render**: lures (`gen_lures.py` → `lures.jsonl`) are rendered deterministically across the 8 surfaces (`render_surfaces.py`). **Decision on URLs (see [`synthetic/README.md`](synthetic/README.md)):** URLs are **realistic** (combosquat / typosquat / RFC-5737 IP-literal / shortener), **not** `.invalid` — a fake TLD would let an LLM detector cheat and inflate scores. Safety = **stored defanged (`hxxp://`, `[.]`) + never resolved**, re-fanged in memory at eval (`parse_eml.refang()`) so the detector sees a realistic string. Optional realism subset from [URLhaus](https://urlhaus.abuse.ch/) (CC0) / [OpenPhish](https://openphish.com/) / [PhishTank](https://phishtank.org/) (defanged dead URLs).

**Where each class comes from:** malicious phishing-family positive ← Nazario
(`threat_type=phishing`) + SpamAssassin (`threat_type=spam`); **benign ←
SpamAssassin ham** (the FPR negatives). Content type lives in `category`.
Optionally diversify benign later with Enron / modern transactional mail.

## Corpora analysis (fetched 2026-06-20)
| Source | Size | License | Format | What it covers | Verdict |
|--------|------|---------|--------|----------------|---------|
| **SpamAssassin public corpus** (`spamassassin.apache.org/old/publiccorpus`) | ~6 tarballs (easy/hard ham + spam, 2002–03) | free / redistributable | **full `.eml` (headers + HTML)** | benign ham + early spam | ✅ **best for the ham/benign split + structural realism**; dated; "spam" ≠ modern phishing |
| **Nazario phishing corpus** | ~thousands (2005-era **+ 2020–2023**) | **CC-BY-4.0** ✓ | full `.eml` phishing | canonical hand-screened phishing | ✅ **best *real* phishing `.eml`** (headers/HTML/links); **recent yearly mailboxes 2020–2023 included** → modern coverage; widely cited |
| **ealvaradob/phishing-dataset** (HF) | 10–100k | **Apache-2.0** ✓ | aggregate; configs incl. `texts/urls/webpages/emails` | mixed phishing text/URLs | ⚠️ license clean, but sample fetch returned empty — **format unconfirmed (likely body-text)**; verify the `emails` config before relying on it |
| **zefang-liu/phishing-email-dataset** (HF) | 18,650 | LGPL-3.0 | **body-text only, lowercased + tokenized (lossy)** | `Email Text` + `Safe/Phishing` | ⚠️ degraded text, awkward license — **avoid as primary** |
| **darkknight25/phishing_benign_email_dataset** (HF) | 200 | MIT ✓ | **synthetic**, rich labels: `intent / technique / target / spoofed_sender` | credential/banking lures | ✅ **excellent label taxonomy + a few seeds**; tiny, synthetic, body-only |
| **cybersectony/PhishingEmailDetectionv2.0** (HF) | 200k | **none** ❌ | `content` (email *or* URL) + multiclass `label` | emails + URLs | ❌ **no license — do not use/redistribute** |

## Coverage & gaps
- **Covered well:** phishing/spam **body text** at scale; **full-`.eml` ham** (SpamAssassin); a clean **lure label taxonomy** (darkknight25: intent/technique/target/spoofed_sender → maps to our `scenario`/`threat_type`).
- **Gap 1 — modern full-`.eml` phishing is scarce.** Aggregates strip to body text (no HTML/headers/links). → fill with **real captures + synthetic**. This is *why* the sync asked for a synthetic pipeline, not corpora alone.
- **Gap 2 — explicit malicious-URL annotation is rare.** Most corpora don't mark the bad link. → **extract** URLs from real emails, or get clean ground truth from **synthetic**.
- **Gap 3 — recency (mitigated).** SpamAssassin ham/spam is 2002–05, but **Nazario now includes 2020–2023 mailboxes** (`fetch_corpora.sh` pulls them) — ~23% of sampled phishing is 2020–2023 (real modern DKIM/SendGrid headers, current brands). Synthetic lures still add brands the captures lack (MS365/DocuSign/crypto). Benign is still dated (2002–05 ham) — diversify with Enron/modern later.

## Why synthetic (measured on our corpus)
The real `.eml` are **not plaintext** — they have ordinary HTML — but they are nearly empty on the *adversarial structural evasions* the paper targets (P2). Measured over the **6,907 fetched malicious `.eml`**:

| Surface | In real corpus | |
|---|---|---|
| HTML body | **63%** | plenty — ordinary HTML |
| CSS-hidden text (`font-size:0` / `display:none` / `color:#fff`) | **4%** | sparse |
| multipart-mismatch (benign `text/plain` + malicious `text/html`) | **~0%** | they're single-part HTML |
| PDF-attachment payload | **0%** | absent |
| URL fragmentation / zero-width | rare | pre-dates these anti-detector tricks |

So the real data is structurally **naive, not empty**: rich in benign HTML, near-absent on the modern evasions an attacker uses against an LLM agent. Synthetic's value is therefore **not** "add HTML" — it is:
1. **coverage** of the 0–4% evasion surfaces (CSS-hidden, multipart-mismatch, PDF, fragmentation);
2. **content-matched controlled variants** — the *same* lure across all 8 surfaces, so a detection drop is attributable to *structure*, not content (impossible with found data);
3. modern brands + clean `malicious_urls` ground truth.

Always report **real vs. synthetic separately** — synthetic can carry generation artifacts a detector might exploit.

## Fetched corpora (2026-06-20) — `scripts/fetch_corpora.sh`
Run the script to materialize the full corpus locally (gitignored; not in git — size + PII). Counts:

| Class | Source | Count | Dir |
|-------|--------|-------|-----|
| benign (ham) | SpamAssassin easy_ham | 2,501 | `ham/spamassassin_easy/` |
| benign (ham) | SpamAssassin hard_ham | 251 | `ham/spamassassin_hard/` |
| phishing | Nazario (mbox→.eml; 2005-era + 2020–2023) | 5,935 | `real/nazario/` |
| phishing (419/lottery/etc.) | SpamAssassin spam + spam_2 | 1,897 | `real/spamassassin_spam/` |

**Totals: 2,752 benign · 7,832 malicious** (Nazario 5,935 + SA-spam 1,897). Committed to git: `scripts/` (fetch + build pipeline), `manifest.jsonl`, `corpus/` (the curated `.eml` benchmark), `STATS.md`, `ATTRIBUTION.md`. Full upstream corpus + raw archives are gitignored — `scripts/fetch_corpora.sh` regenerates them. Licenses + PII/defang rules: `ATTRIBUTION.md`.

## Data sources & citation
The emails are **established research corpora**, not ad-hoc samples — both are standard in the phishing/spam-detection literature. Attribution is required for Nazario (CC-BY-4.0):
- **Nazario Phishing Corpus** — J. Nazario, *Phishing Corpus*, https://monkey.org/~jose/phishing/ — **CC-BY-4.0** (derivatives + commercial use OK, **attribution required**). Hand-classified real phishing; widely cited (Google Scholar: "nazario phishingcorpus").
- **SpamAssassin Public Corpus** — Apache SpamAssassin, https://spamassassin.apache.org/old/publiccorpus/ — freely redistributable; the standard ham/spam benchmark.

Cite both in the paper's dataset section; see `ATTRIBUTION.md` for full license text + PII/defang handling.

## Recommendation (Phase 1)
- **Ham/benign:** SpamAssassin `easy_ham` + `hard_ham` (full `.eml`).
- **Phishing-family positives:** Nazario phishing (CC-BY-4.0) + SpamAssassin spam.
- **Scale + structure + labels:** synthetic, using darkknight25's intent/technique taxonomy + defanged URL-feed domains.
- **Avoid as primary:** zefang-liu (lossy / LGPL), cybersectony (no license).

## Ethics
Defang live malicious URLs (`hxxp://…`) or use attacker-controlled placeholder domains in any committed/published artifact. Never ship live, currently-harmful links.

## Layout (processed data only — raw corpora are transient)
```
dataset/phishing/
├── README.md         # this file
├── STATS.md          # live data card (auto-generated by scripts/build_manifest.py)
├── ATTRIBUTION.md    # source licenses + PII/defang rules
├── manifest.jsonl    # curated benchmark records (processed: deduped/parsed/labeled/sampled)
├── corpus/           # 600 curated .eml (the committed benchmark)
├── synthetic/        # lures.jsonl + eml/ + manifest (synthetic, defanged)
└── scripts/          # fetch_corpora.sh, parse_eml.py, dedup.py, build_manifest.py, gen_lures.py, render_surfaces.py

# transient, NOT committed (regenerated on demand by scripts/fetch_corpora.sh, gitignored):
#   ham/  real/  _raw/   ← the raw upstream corpus
# shared, at dataset/ level:
#   ../schema/email_record.schema.json   ../sources/NOTES.md
```
The raw corpora are a build input, not an artifact — only the **processed** benchmark (`manifest.jsonl`, `corpus/`, `synthetic/`) is kept.

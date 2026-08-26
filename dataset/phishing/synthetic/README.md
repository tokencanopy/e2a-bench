# Synthetic phishing generation — plan

Fills what the real corpora lack (see `../README.md` → "Why synthetic"):
modern lures, the adversarial **structural evasion surfaces** (0–4% in real data),
**content-matched** variants for the controlled comparison, clean `malicious_urls`,
and PII-free / publishable emails.

## Design: generate-then-render (two stages, for reproducibility)
LLM calls are non-deterministic, so we **separate generation from rendering**:
1. **Stage A — generate lures (LLM, run once → committed `lures.jsonl`).**
2. **Stage B — render (deterministic, `lures.jsonl` → `.eml`).**
Stage B is seeded/index-varied and fully reproducible; re-running never needs the API. Commit `lures.jsonl` so the corpus regenerates offline.

## Stage A — lure content (`scripts/gen_lures.py`, LLM)
For each `(scenario × brand × tone)`, prompt an LLM (Claude) to write a realistic lure. Output one JSON record per lure into `lures.jsonl`:
- `subject`, `sender_name`, `sender_domain` (lookalike/placeholder), `body_text`, `body_html` (with a single `{{URL}}` slot), `cta` (call to action), `scenario`, `brand`, `tone`.
- **Axes:** scenarios = credential/account, financial, gift_card, delivery, **MFA/2FA, invoice, doc-share (DocuSign), crypto-wallet** (the modern/thin kinds); brands = Microsoft 365, Google, DocuSign, Amazon, FedEx, PayPal, a bank, a crypto exchange; tone = urgency / reward / authority.
- **Malicious URL** is **realistic** (combosquat/typosquat like `microsoft365-account-security[.]com`, an IP-literal from **RFC 5737** test ranges like `198[.]51[.]100[.]23`, or a shortener like `bit[.]ly/xxxx`) but **stored DEFANGED** (`hxxp://`, every dot `[.]`). Safety = *never resolved* + defanged on disk, **not** a fake TLD (a `.invalid` TLD would be an obvious giveaway that inflates detection and tips off an LLM). Eval re-fangs in memory via `parse_eml.refang()` so the detector sees a real-looking string. Optionally seed real (already-dead, defanged) URLs from **URLhaus** (CC0) / **OpenPhish** / **PhishTank** for a realism subset. Fixed pool ⇒ `malicious_urls` label is exact.
- **QC:** dedupe; an LLM-judge pass scores plausibility; drop low-quality.

## Stage B — structural rendering (`scripts/render_surfaces.py`, deterministic)
Take each lure and emit a valid MIME `.eml` for **each of the 8 surfaces** (Python `email`/`EmailMessage`):
1. **plaintext** — URL visible in the text body
2. **visible HTML** — URL as `<a href>`
3. **CSS-hidden** — lure/URL in `font-size:0`/`color:#fff`/`display:none` (agent reads it, human doesn't)
4. **multipart-mismatch** — benign `text/plain` + malicious `text/html`
5. **subject/header** — payload/URL in Subject or a header
6. **quoted-thread** — payload buried under quoted reply history
7. **PDF attachment** — lure+URL rendered into a PDF text layer, attached
8. **encoded/fragmented** — URL fragmented (Mimecast trick) / quoted-printable / zero-width

Set realistic `From` (display-name spoof), `Date`, `Message-ID`. Do **NOT** write `Authentication-Results` — `auth` is assigned downstream from `sender_auth_condition` (e2a recomputes it; see `../README.md`).

**Controlled-comparison matrix:** K base lures × 8 surfaces ⇒ K×8 `.eml` that share content and differ only in structure → a detection drop is attributable to *structure*, not content.

## Labeling → manifest
Each rendered `.eml` emits an `EmailRecord` (`../../schema/`): `is_malicious=true`, `threat_type=phishing`, `category` (content type), `malicious_urls=[planted URL]`, `surface=[the rendered surface]`, **`provenance.synthetic=true`**, assigned `sender_auth_condition`. Separate `synthetic/manifest.jsonl` (merge with the real-corpus benchmark for eval).

## Sizing (initial)
~40 base lures × 8 surfaces ≈ **320 synthetic `.eml`**, weighted toward the thin/modern kinds (gift_card, delivery, MFA, DocuSign, crypto). Tune to balance the kind distribution in `STATS.md`.

## Ethics / safety
- **Realistic but defanged URLs, never resolved** — `hxxp://…[.]…` form on disk; safety is "we never fetch them" + defang, not a fake TLD. Re-fang only in-memory at eval. Never commit a fanged/live link.
- **No PII** — fully synthetic; this is the publishable half of the benchmark.
- Mark every record `provenance.synthetic=true`.
- Research-scoped templates only.

## Validation (artifact risk)
LLM lures can carry a stylistic "tell." Mitigations: keep **real vs. synthetic results separate** in eval; never train *and* test only on synthetic; optionally run a synthetic-vs-real discriminability check and report it.

## Scripts (implemented in `../scripts/`)
- `gen_lures.py` — **Stage A** (LLM → `lures.jsonl`). Requires `ANTHROPIC_API_KEY`; run once to scale (`--n 40`). Enforces realistic-but-defanged URLs (`hxxp://`, `[.]`, RFC-5737 IPs) + the `{{URL}}` token.
- `render_surfaces.py` — **Stage B** (deterministic; `lures.jsonl` → `eml/*.eml` + `manifest.jsonl` across the 8 surfaces). No API needed.
- TODO: extend `build_manifest.py` to sample/merge synthetic alongside the real corpus.

## Current state
- `lures.jsonl` — **25 seed lures** committed (hand-authored across credential/MFA/doc-share/delivery/gift-card/financial/crypto/invoice; modern brands: MS365, DocuSign, Google, FedEx, DHL, USPS, Amazon, PayPal, Venmo, Coinbase, Binance, LinkedIn, Apple, Netflix, banks…). Scale further with `gen_lures.py`.
- `eml/` + `manifest.jsonl` — **200 synthetic `.eml`** (25 lures × 8 surfaces), **byte-stable** re-renders (deterministic MIME boundaries) via `render_surfaces.py`. Committed (small, PII-free, defanged — the publishable half).

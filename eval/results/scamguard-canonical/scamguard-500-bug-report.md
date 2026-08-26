# Bug report: /v1/inbound/scan returns HTTP 500 on HTML email bodies

**Endpoint:** `POST https://api.checkreality.ai/v1/inbound/scan`
**API version:** v0.1.0 (per scam-guard-api-reference.pdf)
**Severity:** Medium — deterministic server-side crash; silently drops a subset of inputs.

## Summary
When `raw_email` contains real-world HTML markup, the endpoint returns
`500 Internal Server Error` (plain-text body, no JSON error object). The failure
is deterministic — it survives retries and is unrelated to rate limiting (429s we
saw earlier were separate and resolved on their own). It reproduces regardless of
`content_type`; we send `content_type: "text/plain"`, but the body carries HTML
(as many real inbound emails do), and the server still appears to attempt HTML
parsing and crash.

## Scope observed
- 29 of 6,333 inputs (~0.46%) in our benchmark, all HTML-containing emails.
- Every one of the 29 fails deterministically on the raw content.
- Every one of the 29 returns `200` when the HTML tags are stripped from the same
  content — isolating the trigger to the HTML markup, not the surrounding text.

## What it is NOT
- Not rate limiting (429s were separate; these are 500s that never recover).
- Not payload size alone: some inputs fail below 1 KB, others succeed at the full
  8 KB we send.
- Not non-ASCII characters or quoted-printable artifacts (failing inputs have
  near-zero of both).

## Isolation evidence
Request shape:
```
POST /v1/inbound/scan
Authorization: Bearer <key>
{"raw_email": "<content>", "content_type": "text/plain"}
```

1. Full content (real nested HTML) → **500**.
2. Same content with HTML tags removed (regex `<[^>]+>` → space) → **200** (all 29).
3. Prefix binary-search on one input (deeply-nested HTML body):
   - first 2,545 chars → **200**
   - 2,546+ chars → **500**
   The boundary falls inside a run of deeply-nested `<div>/<a>` markup.
4. We could not reproduce with *synthetic* HTML (nested `<div>`×200, unclosed
   `<div><table><tr><td>`×100, styled divs, 400 flat tags — all returned 200), so
   the trigger is some specific real-world HTML construct rather than nesting
   depth or malformed tags in general.

## Impact
A caller submitting real HTML email bodies gets an opaque 500 on a fraction of
traffic. In an evaluation/benchmark context those inputs are dropped from scoring;
in production they would be unscanned (fail-open or fail-closed depending on the
caller's error handling).

## Requests
1. Triage the server-side HTML parse path for `/v1/inbound/scan`.
2. Return a structured error (e.g. `422` with a JSON body) instead of a bare
   `500` so callers can distinguish "cannot parse" from a true outage.
3. We are happy to share the exact 29 payloads (or the minimal failing prefix) to
   help you reproduce — just let us know where to send them.

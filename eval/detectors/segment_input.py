"""Shared content provider — the single source of email text for every detector.

The canonical view comes from e2a's own extractor: `piguard-eval --dump-segments`
writes one JSON line per email holding the typed segments (subject, text_plain,
html_visible, html_hidden, attachment_text) plus the decoded signals. Every
text-only detector flattens those segments into one blob via `content_for`, so it
screens the *exact same content piguard sees* — including hidden HTML and
attachment/PDF text — instead of re-parsing the .eml with a lazy reader.

Provisioning / failure modes (benchmark integrity):
  * PIGUARD_SEGMENTS points at the dump → canonical view (the intended path).
  * PIGUARD_SEGMENTS set but an id is ABSENT from the dump → raises ValueError, so
    the detector records a per-entry error rather than silently scoring a body-only
    reparse (which would drop the attachment/hidden-HTML payload).
  * PIGUARD_SEGMENTS unset → a loud warning + best-effort all-parts fallback, for
    offline development only. NOT valid for a canonical benchmark run.
Note: signals are intentionally NOT surfaced here — text-only detectors consume
segment *content* only.
"""
from __future__ import annotations

import email as _email
import functools
import os
import sys
from email.policy import default as _default_policy

# Order segments are concatenated in. Extraction already emits them in this
# order; we list it explicitly so the flattened text is stable and readable.
_SEGMENT_ORDER = (
    "subject", "text_plain", "html_visible", "html_hidden", "attachment_text",
)


@functools.lru_cache(maxsize=2)
def _load_dump(path: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                d = _email_json_loads(line)
                out[d["id"]] = d
    return out


def _email_json_loads(line: str) -> dict:
    import json
    return json.loads(line)


def flatten(segments: list[dict]) -> str:
    """Concatenate segment contents into one text blob (canonical downcast).

    Skips a segment whose content is already wholly contained in the accumulated
    text, so a multipart/alternative whose text/plain == html_visible isn't doubled
    (the multipart_mismatch surface, where the parts differ, is preserved)."""
    rank = {t: i for i, t in enumerate(_SEGMENT_ORDER)}
    ordered = sorted(segments, key=lambda s: rank.get(s.get("type", ""), len(rank)))
    out: list[str] = []
    acc = ""
    for s in ordered:
        c = s.get("content")
        if not c or c in acc:
            continue
        out.append(c)
        acc = "\n".join(out)
    return acc


def _segments_for(entry: dict) -> list[dict] | None:
    """Return the canonical segments for an entry, or None if no dump is configured.
    Raises ValueError if the dump is set but the id is missing or recorded an error."""
    path = os.environ.get("PIGUARD_SEGMENTS")
    if not (path and os.path.exists(path)):
        return None
    rec = _load_dump(path).get(entry["id"])
    if rec is None:
        raise ValueError(f"segments: id {entry['id']!r} absent from PIGUARD_SEGMENTS dump")
    if rec.get("error"):
        raise ValueError(f"extract: {rec['error']}")
    return rec.get("segments", [])


def content_for(entry: dict, base_dir: str = ".", max_chars: int | None = None) -> str:
    """Full email text for a manifest entry, from the canonical e2a segments.

    Raises ValueError if the dump is configured but this id is missing or recorded
    an extraction error (so the detector records the error rather than scoring
    body-only text). `max_chars` bounds the returned length (None = no cap;
    callers hitting size-limited APIs should pass one)."""
    segs = _segments_for(entry)
    if segs is None:
        _warn_once()
        text = _fallback_all_parts(entry, base_dir)
    else:
        text = flatten(segs)
    return text[:max_chars] if max_chars else text


def parts_for(entry: dict, base_dir: str = ".",
              max_body_chars: int | None = None) -> tuple[str, str, str]:
    """(subject, from, body) for detectors that want structured fields, sourced
    from the canonical segments. Subject/from come from their segment refs; the
    rest (text_plain, html_visible, html_hidden, attachment_text) are flattened
    into body. Falls back to header-parsed subject/from + all-parts body when no
    dump is set. `max_body_chars` bounds the body length (None = no cap)."""
    segs = _segments_for(entry)
    if segs is None:
        _warn_once()
        subject, from_, body = _fallback_parts(entry, base_dir)
    else:
        subject = next((s.get("content", "") for s in segs
                        if s.get("type") == "subject" and s.get("ref") == "subject"), "")
        from_ = next((s.get("content", "") for s in segs
                      if s.get("type") == "subject" and s.get("ref") == "from"), "")
        body_segs = [s for s in segs
                     if not (s.get("type") == "subject" and s.get("ref") in ("subject", "from"))]
        body = flatten(body_segs)
    if max_body_chars:
        body = body[:max_body_chars]
    return subject, from_, body


_warned = False


def _warn_once() -> None:
    global _warned
    if not _warned:
        print("segment_input: PIGUARD_SEGMENTS unset — using Python fallback parser "
              "(set it to a `piguard-eval --dump-segments` file to mirror e2a exactly). "
              "This is NOT a canonical benchmark run.", file=sys.stderr)
        _warned = True


def _parse_eml(eml_path: str, base_dir: str):
    with open(os.path.join(base_dir, eml_path), "rb") as f:
        return _email.message_from_bytes(f.read(), policy=_default_policy)


def _text_parts(msg) -> list[str]:
    chunks: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    chunks.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_content())
        except Exception:
            pass
    return chunks


def _fallback_all_parts(entry: dict, base_dir: str) -> str:
    """Best-effort: subject + EVERY text part (plain and html), not just the first.
    Safety net for environments without a segments dump; does not reproduce e2a's
    hidden-HTML split, charset transcoding, attachment text, or signals.

    For CSV-sourced entries that have no eml file, reads inline detector_input."""
    eml_path = entry.get("eml_path")
    if not eml_path:
        subject, _from, body = _detector_input_parts(entry)
        return f"{subject}\n{body}".strip()
    msg = _parse_eml(eml_path, base_dir)
    chunks = [str(msg.get("Subject", ""))] + _text_parts(msg)
    return "\n".join(c for c in chunks if c)


def _fallback_parts(entry: dict, base_dir: str) -> tuple[str, str, str]:
    """Best-effort (subject, from, body) from raw .eml or inline detector_input."""
    eml_path = entry.get("eml_path")
    if not eml_path:
        return _detector_input_parts(entry)
    msg = _parse_eml(eml_path, base_dir)
    subject = str(msg.get("Subject", ""))
    from_ = str(msg.get("From", ""))
    body = "\n".join(c for c in _text_parts(msg) if c)
    return subject, from_, body


def _detector_input_parts(entry: dict) -> tuple[str, str, str]:
    """Extract (subject, from, body) from the inline detector_input dict.

    Used for CSV-sourced manifest entries that have no on-disk .eml file."""
    di = entry.get("detector_input") or {}
    subject = di.get("subject") or ""
    from_ = di.get("from") or ""
    body_d = di.get("body") or {}
    text = body_d.get("text") or ""
    html = body_d.get("html") or ""
    body = (text + "\n" + html).strip() if (text or html) else ""
    return str(subject), str(from_), body

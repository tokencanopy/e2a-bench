#!/usr/bin/env python3
"""eml_extract.py — pull every detection-relevant field out of a single .eml.

One canonical RFC822 parser for the whole eval pipeline. Detectors historically
each carried their own lossy `_extract_text`; this consolidates that into one
extractor that also recovers fields they dropped: HTML-stripped text, hyperlink
targets, attachments, and the sender-auth verdicts the .eml *claims*.

Two surfaces:
  * `extract(eml_path, base_dir) -> ExtractedEmail` — structured record.
  * CLI — `python3 eval/eml_extract.py <eml> [--text] [--no-refang]` — inspect
    what a detector would see for one message.

Synthetic samples store URLs defanged (hxxp://, foo[.]com) so on-disk artifacts
stay non-clickable. `refang=True` (default) restores them so a detector sees a
realistic URL; flip it off to inspect the raw on-disk form.

NOTE on auth: the `auth` field is what the .eml's headers *claim* (parsed from
Authentication-Results / Received-SPF). It is NOT ground truth — e2a recomputes
SPF/DKIM/DMARC live from envelope+IP+DNS and ignores these headers (see
dataset/schema/email_record.schema.json). Treat it as a detector feature only.
"""
from __future__ import annotations

import argparse
import email
import json
import re
from dataclasses import asdict, dataclass, field
from email.message import Message
from email.policy import default as _default_policy
from html import unescape
from html.parser import HTMLParser

_URL_RE = re.compile(r'https?://[^\s"\'<>)\]}]+', re.I)
_AUTH_VERDICT_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*(\w+)', re.I)


def refang(value: str) -> str:
    """Restore a defanged URL (hxxp[s]://, [.]) to its realistic form. No-op if
    already fanged."""
    return (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("[:]", ":")
    )


class _HTMLToText(HTMLParser):
    """Strip tags to visible text and collect href/src link targets."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self.links: list[str] = []
        self._skip = 0  # depth inside <script>/<style>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        for name, val in attrs:
            if name in ("href", "src") and val:
                self.links.append(val)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "\n".join(self._chunks)).strip()


def _html_to_text_and_links(html: str) -> tuple[str, list[str]]:
    parser = _HTMLToText()
    try:
        parser.feed(html)
    except Exception:
        # Malformed HTML: fall back to a crude tag strip.
        return unescape(re.sub(r"<[^>]+>", " ", html)).strip(), []
    return parser.text(), parser.links


def _addresses(msg: Message, header: str) -> list[str]:
    values = msg.get_all(header)
    if not values:
        return []
    out: list[str] = []
    for raw in values:
        for piece in str(raw).split(","):
            piece = piece.strip()
            if piece:
                out.append(piece)
    return out


def _decode(part: Message) -> str:
    try:
        return part.get_content()
    except Exception:
        # get_content() chokes on a bogus/garbled charset declaration (common in
        # old phishing corpora, e.g. "iso-7163-9"). Decode the raw payload with
        # the declared charset if usable, else fall back — never raise.
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        for charset in (part.get_content_charset(), "utf-8", "latin-1"):
            if not charset:
                continue
            try:
                return payload.decode(charset, errors="replace")
            except LookupError:
                continue
        return payload.decode("utf-8", errors="replace")


def _parse_auth(msg: Message) -> dict[str, str]:
    auth: dict[str, str] = {}
    for header in msg.get_all("Authentication-Results") or []:
        for mech, verdict in _AUTH_VERDICT_RE.findall(str(header)):
            auth.setdefault(mech.lower(), verdict.lower())
    if "spf" not in auth:
        spf = msg.get("Received-SPF")
        if spf:
            auth["spf"] = str(spf).strip().split()[0].lower()
    if "dkim" not in auth and msg.get("DKIM-Signature"):
        auth["dkim"] = "present"
    return auth


@dataclass
class ExtractedEmail:
    eml_path: str
    from_: str
    to: list[str]
    cc: list[str]
    reply_to: list[str]
    subject: str
    date: str
    text: str            # text/plain part (verbatim)
    html: str            # text/html part (verbatim)
    text_from_html: str  # html stripped to visible text
    urls: list[str]      # deduped, refanged, from body text + html hrefs
    attachments: list[dict] = field(default_factory=list)
    auth: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    has_html: bool = False
    has_attachment: bool = False

    @property
    def body(self) -> str:
        """Visible text from BOTH the text/plain and text/html parts.

        The html_visible / css_hidden / multipart_mismatch attack surfaces hide
        the payload in one MIME part while the other is a benign decoy, so we
        must never prefer one over the other — a detector that sees only the
        decoy misses the attack. Parts are merged, skipping the duplicate case
        where one already contains the other (the common nested-alternative)."""
        text = self.text.strip()
        html_text = self.text_from_html.strip()
        if not html_text:
            return text
        if not text:
            return html_text
        if text in html_text:
            return html_text
        if html_text in text:
            return text
        return f"{text}\n\n{html_text}"

    def body_with_urls(self, max_chars: int | None = None) -> str:
        """Body with the recovered (refanged) link targets appended."""
        out = self.body
        if self.urls:
            out += "\n\nLinks:\n" + "\n".join(self.urls)
        return out[:max_chars] if max_chars else out

    def detector_text(
        self,
        max_chars: int | None = None,
        include_from: bool = False,
        include_urls: bool = False,
    ) -> str:
        """Subject + body as a single string — the canonical detector input.

        `include_urls` appends the recovered (refanged) hyperlink targets, which
        is the threat signal for phishing whose body text looks benign.
        """
        head = f"Subject: {self.subject}"
        if include_from:
            head += f"\nFrom: {self.from_}"
        out = f"{head}\n\n{self.body}"
        if include_urls and self.urls:
            out += "\n\nLinks:\n" + "\n".join(self.urls)
        return out[:max_chars] if max_chars else out

    def to_dict(self) -> dict:
        d = asdict(self)
        d["from"] = d.pop("from_")
        d["body"] = self.body
        return d


def extract(eml_path: str, base_dir: str = ".", refang_urls: bool = True) -> ExtractedEmail:
    import os

    full_path = eml_path if os.path.isabs(eml_path) else os.path.join(base_dir, eml_path)
    with open(full_path, "rb") as f:
        raw = f.read()
    if raw[:5] == b"From ":  # strip a leading mbox envelope line if present
        nl = raw.find(b"\n")
        if nl != -1:
            raw = raw[nl + 1:]

    msg = email.message_from_bytes(raw, policy=_default_policy)

    text, html = "", ""
    attachments: list[dict] = []
    leaves = [p for p in (msg.walk() if msg.is_multipart() else [msg]) if not p.is_multipart()]
    for part in leaves:
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True)
            attachments.append({
                "filename": filename or "",
                "content_type": part.get_content_type(),
                "size": len(payload) if payload else 0,
            })
            continue
        # startswith, not ==, because malformed corpora produce mangled types
        # like "text/html content-transfer-encoding: 8bit" from folded headers.
        ct = part.get_content_type()
        if ct.startswith("text/plain") and not text:
            text = _decode(part)
        elif ct.startswith("text/html") and not html:
            html = _decode(part)

    # Last-resort recovery: a malformed message can leave every leaf untyped or
    # mistyped. Rather than emit an empty body, decode the first non-empty inline
    # leaf and route it by sniffing for markup.
    if not text.strip() and not html.strip():
        for part in leaves:
            if part.get_filename() or (part.get_content_disposition() or "").lower() == "attachment":
                continue
            content = _decode(part)
            if content.strip():
                if "<html" in content.lower() or "<body" in content.lower() or "<a " in content.lower():
                    html = content
                else:
                    text = content
                break

    text_from_html, html_links = _html_to_text_and_links(html) if html else ("", [])

    # Extract via the URL regex from every source (body text, raw HTML, and
    # href/src targets). Routing hrefs through the regex too means a malformed
    # target like "C:\path\http://real.url" contributes only its embedded URL,
    # not the junk wrapper.
    seen: set[str] = set()
    urls: list[str] = []
    for source in [text, html_text_source(html), *html_links]:
        source = refang(source) if refang_urls else source
        for u in _URL_RE.findall(source):
            if u not in seen:
                seen.add(u)
                urls.append(u)

    return ExtractedEmail(
        eml_path=eml_path,
        from_=str(msg.get("From") or "").strip(),
        to=_addresses(msg, "To"),
        cc=_addresses(msg, "Cc"),
        reply_to=_addresses(msg, "Reply-To"),
        subject=str(msg.get("Subject") or "").strip(),
        date=str(msg.get("Date") or "").strip(),
        text=text,
        html=html,
        text_from_html=text_from_html,
        urls=urls,
        attachments=attachments,
        auth=_parse_auth(msg),
        content_type=msg.get_content_type(),
        has_html=bool(html),
        has_attachment=bool(attachments),
    )


def html_text_source(html: str) -> str:
    """URLs sometimes live only in raw HTML attributes the stripper drops; scan
    the unescaped HTML too so href/src in non-anchor tags aren't missed."""
    return unescape(html) if html else ""


def _main() -> None:
    parser = argparse.ArgumentParser(description="Extract detection-relevant fields from a .eml")
    parser.add_argument("eml_path")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--no-refang", action="store_true", help="keep URLs defanged (raw on-disk form)")
    parser.add_argument("--text", action="store_true", help="print the detector_text string instead of JSON")
    args = parser.parse_args()

    rec = extract(args.eml_path, args.base_dir, refang_urls=not args.no_refang)
    if args.text:
        print(rec.detector_text(include_from=True))
    else:
        print(json.dumps(rec.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _main()

"""Parse a .eml into the fields the schema's detector_input needs.
Mirrors e2a's MessageView (subject/from/body{text,html}). Auth is NOT parsed
here — it is assigned downstream from sender_auth_condition (e2a recomputes
SPF/DKIM/DMARC live and ignores the .eml's Authentication-Results header)."""
import email, re
from email import policy

_URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.I)


def refang(u):
    """Restore a defanged synthetic URL (hxxp[s]://, [.]) to its realistic form.
    Eval calls this so the detector sees a real-looking URL while on-disk artifacts
    stay defanged + non-clickable. No-op on already-fanged URLs."""
    return u.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")


def _decode_part(part):
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        cs = part.get_content_charset() or "utf-8"
        return payload.decode(cs, errors="replace")
    except Exception:
        return ""


def parse_eml(path):
    raw = open(path, "rb").read()
    if raw[:5] == b"From ":               # strip leading mbox envelope line if present
        nl = raw.find(b"\n")
        if nl != -1:
            raw = raw[nl + 1:]
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    subject = str(msg.get("Subject") or "").strip()
    sender = str(msg.get("From") or "").strip()
    date = str(msg.get("Date") or "").strip()
    text, html, has_attachment = "", "", False
    for p in (msg.walk() if msg.is_multipart() else [msg]):
        if p.is_multipart():
            continue
        if p.get_filename():
            has_attachment = True
        ct = p.get_content_type()
        if ct == "text/plain" and not text:
            text = _decode_part(p)
        elif ct == "text/html" and not html:
            html = _decode_part(p)
    urls = _URL_RE.findall(f"{text} {html}")
    return {
        "subject": subject, "from": sender, "date": date,
        "text": text, "html": html, "urls": urls,
        "has_html": bool(html), "has_attachment": has_attachment,
        "content_type": msg.get_content_type(),
    }

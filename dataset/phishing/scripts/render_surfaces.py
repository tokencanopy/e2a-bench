#!/usr/bin/env python3
"""Stage B of synthetic generation: render lures.jsonl into MIME .eml across the
8 structural surfaces. Deterministic (no RNG, no now()) → reproducible.

K lures × 8 surfaces = K×8 content-matched .eml (same lure, structure varies) —
the controlled comparison that isolates the structural effect. See
../synthetic/README.md. Run: python3 scripts/render_surfaces.py"""
import os, json, textwrap, html as htmllib
from email.message import EmailMessage

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LURES, OUT_EML, OUT_MANIFEST = "synthetic/lures.jsonl", "synthetic/eml", "synthetic/manifest.jsonl"
BASE_DATE, RECIPIENT = "Mon, 01 Jun 2026 09:00:00 -0700", "user@example.com"

SURFACES = ["plaintext", "html_visible", "css_hidden", "multipart_mismatch",
            "subject_header", "quoted_thread", "pdf_attachment", "encoded_fragmented"]

# render-surface -> schema `surface[]` enum values (schema/email_record.schema.json)
SCHEMA_SURFACE = {
    "plaintext": ["plaintext_body", "hyperlink"],
    "html_visible": ["html_body", "hyperlink"],
    "css_hidden": ["html_hidden_css", "hyperlink"],
    "multipart_mismatch": ["multipart_mismatch", "html_body", "hyperlink"],
    "subject_header": ["header", "hyperlink"],
    "quoted_thread": ["quoted_thread", "hyperlink"],
    "pdf_attachment": ["pdf_attachment"],
    "encoded_fragmented": ["encoded_obfuscated", "html_body"],
}


def _base_msg(lure, surface, subject=None):
    m = EmailMessage()
    m["From"] = f'{lure["sender_name"]} <noreply@{lure["sender_domain"]}>'
    m["To"] = RECIPIENT
    m["Subject"] = lure["subject"] if subject is None else subject
    m["Date"] = BASE_DATE
    m["Message-ID"] = f'<{lure["id"]}-{surface}@e2a-synth.invalid>'
    return m


def _minimal_pdf(text):
    """Tiny one-page PDF with an extractable text layer (no external deps)."""
    # wrap (don't truncate) so the URL survives intact; keep long URL tokens whole
    lines = []
    for l in (text.splitlines() or [text]):
        if l.strip():
            lines += textwrap.wrap(l, 90, break_long_words=False, break_on_hyphens=False) or [l]
    lines = lines[:40] or [" "]
    esc = lambda s: s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    content = "BT /F1 11 Tf 50 760 Td 14 TL\n" + "\n".join(f"({esc(l)}) Tj T*" for l in lines) + "\nET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
    ]
    pdf, offs = "%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(pdf)); pdf += f"{i} 0 obj\n{o}\nendobj\n"
    xref = len(pdf)
    pdf += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n" + "".join(f"{o:010d} 00000 n \n" for o in offs)
    pdf += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return pdf.encode("latin-1", errors="replace")


# synthetic lure scenario -> shared content category (matches build_manifest.categorize)
LURE_CATEGORY = {
    "credential_account": "credential", "mfa": "credential", "doc_share": "credential",
    "financial": "financial", "invoice": "financial", "crypto": "financial",
    "gift_card": "gift_card", "delivery": "delivery",
}


def render(lure, surface):
    url = lure["malicious_url"]
    bt = lure["body_text"].replace("{{URL}}", url)
    bh = lure["body_html"].replace("{{URL}}", url)
    m = _base_msg(lure, surface)
    if surface == "plaintext":
        m.set_content(bt)
    elif surface == "html_visible":
        m.set_content(bt); m.add_alternative(f"<html><body>{bh}</body></html>", subtype="html")
    elif surface == "css_hidden":
        m.set_content("Thank you for being a valued customer.")
        hidden = f'<div style="font-size:0;color:#ffffff;display:none">{bh}</div>'
        m.add_alternative(f"<html><body><p>Thank you for being a valued customer.</p>{hidden}</body></html>", subtype="html")
    elif surface == "multipart_mismatch":
        m.set_content("Thanks — no action needed on your end.")          # benign text/plain
        m.add_alternative(f"<html><body>{bh}</body></html>", subtype="html")  # malicious text/html
    elif surface == "subject_header":
        m.replace_header("Subject", f'{lure["subject"]} — verify now: {url}')
        m.set_content("Please see the subject line.")
    elif surface == "quoted_thread":
        quoted = "\n".join("> " + l for l in ["Hi team,", "Forwarding the notice below for action.", "Thanks,", "IT"])
        m.set_content(f"{quoted}\n\n----- Forwarded message -----\n{bt}")
    elif surface == "pdf_attachment":
        m.set_content("Please see the attached document for details.")
        m.add_attachment(_minimal_pdf(bt), maintype="application", subtype="pdf",
                         filename=f'{lure["scenario"]}_document.pdf')
    elif surface == "encoded_fragmented":
        frag = "".join(f"<span>{htmllib.escape(c)}</span>" for c in url)   # Mimecast-style URL fragmentation
        m.set_content(bt.replace(url, "(link in HTML)"))
        m.add_alternative(f"<html><body>{bh.replace(url, frag)}</body></html>", subtype="html")
    else:
        raise ValueError(surface)
    # deterministic MIME boundaries -> byte-stable re-renders (no spurious git churn)
    bi = 0
    for part in m.walk():
        if part.get_content_maintype() == "multipart":
            part.set_boundary(f"==e2a-{lure['id']}-{surface}-{bi}==")
            bi += 1
    return m.as_bytes()


def main():
    os.makedirs(OUT_EML, exist_ok=True)
    lures = [json.loads(l) for l in open(LURES) if l.strip()]
    n = 0
    with open(OUT_MANIFEST, "w") as man:
        for li, lure in enumerate(lures):
            for surface in SURFACES:
                raw = render(lure, surface)
                tid = f'{lure["id"]}_{surface}'
                open(f"{OUT_EML}/{tid}.eml", "wb").write(raw)
                # deterministic auth mix: most spoofed, some verified (authenticated phishing)
                auth = "verified" if (li + SURFACES.index(surface)) % 5 == 0 else "spoofed"
                man.write(json.dumps({
                    "id": tid,
                    "eml_path": f"dataset/phishing/{OUT_EML}/{tid}.eml",
                    "label": {"is_malicious": True, "threat_type": "phishing",
                              "category": LURE_CATEGORY.get(lure["scenario"], "other"),
                              "malicious_urls": [lure["malicious_url"]]},
                    "surface": SCHEMA_SURFACE[surface],
                    "detector_input": {"from": f'{lure["sender_name"]} <noreply@{lure["sender_domain"]}>',
                                       "subject": lure["subject"]},
                    "provenance": {"source": "synthetic", "synthetic": True, "source_id": lure["id"]},
                    "sender_auth_condition": auth,
                    "split": "synthetic",
                }) + "\n")
                n += 1
    print(f"rendered {n} synthetic .eml ({len(lures)} lures x {len(SURFACES)} surfaces) -> {OUT_EML}/ + {OUT_MANIFEST}")


if __name__ == "__main__":
    main()

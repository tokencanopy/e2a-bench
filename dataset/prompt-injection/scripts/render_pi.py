#!/usr/bin/env python3
"""Stage B (prompt injection): embed each payload (an injection instruction) into a
benign CARRIER email across the 8 structural surfaces -> eml/ + manifest.jsonl.
Deterministic (no RNG/now()) → reproducible.

threat_type is direct vs indirect by WHERE the injection sits: main body/subject
= direct; nested in a quoted thread or an attachment = indirect.
Run: python3 scripts/render_pi.py"""
import os, json, textwrap, html as htmllib
from email.message import EmailMessage

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PAYLOADS, OUT_EML, OUT_MANIFEST = "payloads.jsonl", "eml", "manifest.jsonl"
BASE_DATE, RECIPIENT = "Mon, 01 Jun 2026 09:00:00 -0700", "user@example.com"
SENDER = "Alex Partner <alex@external-vendor.example>"
BENIGN = "Hi, just following up on the items below — let me know if you need anything else.\nThanks,\nAlex"

SURFACES = ["plaintext", "html_visible", "css_hidden", "multipart_mismatch",
            "subject_header", "quoted_thread", "pdf_attachment", "encoded_fragmented"]
INDIRECT = {"quoted_thread", "pdf_attachment"}   # injection nested in 3rd-party/retrieved content
SCHEMA_SURFACE = {
    "plaintext": ["plaintext_body"], "html_visible": ["html_body"], "css_hidden": ["html_hidden_css"],
    "multipart_mismatch": ["multipart_mismatch", "html_body"], "subject_header": ["header"],
    "quoted_thread": ["quoted_thread"], "pdf_attachment": ["pdf_attachment"],
    "encoded_fragmented": ["encoded_obfuscated", "html_body"],
}


def _subject(p):
    return (p.get("carrier_subject") or "Re: Project update").strip()[:180] or "Re: Project update"


def _sender(p):
    return (p.get("carrier_sender") or SENDER).strip() or SENDER


def _carrier_intro(p):
    if p.get("carrier_body"):
        return p["carrier_body"]
    if p.get("source") == "llmail-inject":
        return "Please review the email content below."
    return BENIGN


def _header_fragment(text, limit=120):
    return " ".join(text.split())[:limit]


def _minimal_pdf(text):
    lines = []
    for l in (text.splitlines() or [text]):
        if l.strip():
            lines += textwrap.wrap(l, 90, break_long_words=False, break_on_hyphens=False) or [l]
    lines = lines[:40] or [" "]
    esc = lambda s: s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    content = "BT /F1 11 Tf 50 760 Td 14 TL\n" + "\n".join(f"({esc(l)}) Tj T*" for l in lines) + "\nET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
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


def render(p, surface):
    inj = p["injection_text"]
    subject = _subject(p)
    carrier = _carrier_intro(p)
    m = EmailMessage()
    m["From"], m["To"], m["Date"] = _sender(p), RECIPIENT, BASE_DATE
    m["Message-ID"] = f'<{p["id"]}-{surface}@e2a-synth.invalid>'
    m["Subject"] = subject
    if surface == "plaintext":
        m.set_content(f"{carrier}\n\n{inj}")
    elif surface == "html_visible":
        m.set_content(carrier)
        m.add_alternative(f"<html><body><p>{carrier}</p><p>{htmllib.escape(inj)}</p></body></html>", subtype="html")
    elif surface == "css_hidden":
        m.set_content(carrier)
        m.add_alternative(f'<html><body><p>{carrier}</p><div style="font-size:0;color:#ffffff;display:none">{htmllib.escape(inj)}</div></body></html>', subtype="html")
    elif surface == "multipart_mismatch":
        m.set_content(carrier)   # benign text/plain
        m.add_alternative(f"<html><body><p>{carrier}</p><p>{htmllib.escape(inj)}</p></body></html>", subtype="html")  # injected html
    elif surface == "subject_header":
        m.replace_header("Subject", f"Re: Project update — {_header_fragment(inj)}")
        m.set_content(carrier)
    elif surface == "quoted_thread":
        quoted = "\n".join("> " + l for l in [carrier, "", "On Mon, a colleague wrote:", inj])
        m.set_content(f"Looks good to me — see the thread below.\n\n{quoted}")
    elif surface == "pdf_attachment":
        m.set_content("Please see the attached notes for details.")
        m.add_attachment(_minimal_pdf(f"{carrier}\n\n{inj}"), maintype="application", subtype="pdf", filename="meeting_notes.pdf")
    elif surface == "encoded_fragmented":
        frag = "".join(f"<span>{htmllib.escape(c)}</span>" for c in inj)
        m.set_content(carrier)
        m.add_alternative(f"<html><body><p>{carrier}</p><p>{frag}</p></body></html>", subtype="html")
    else:
        raise ValueError(surface)
    if m.is_multipart():
        m.set_boundary(f"e2a-{p['id']}-{surface}")
    return m.as_bytes()


def main():
    os.makedirs(OUT_EML, exist_ok=True)
    payloads = [json.loads(l) for l in open(PAYLOADS) if l.strip()]
    n = direct = indirect = 0
    with open(OUT_MANIFEST, "w") as man:
        for pi, p in enumerate(payloads):
            for surface in SURFACES:
                raw = render(p, surface)
                tid = f'{p["id"]}_{surface}'
                open(f"{OUT_EML}/{tid}.eml", "wb").write(raw)
                tt = "prompt_injection_indirect" if p.get("source") == "agentdojo" or surface in INDIRECT else "prompt_injection_direct"
                if tt == "prompt_injection_indirect":
                    indirect += 1
                else:
                    direct += 1
                auth = ("verified", "spoofed", "unauthenticated")[(pi + SURFACES.index(surface)) % 3]
                source = p["source"] if p["source"] in {"injecagent", "llmail-inject", "agentdojo"} else "handcrafted"
                notes = None
                if p["source"] == "llmail-inject":
                    notes = (
                        "LLMail-Inject payload re-rendered into e2a email-native "
                        "detector benchmark; original challenge measured agent tool-call ASR."
                    )
                elif p["source"] == "agentdojo":
                    notes = (
                        "AgentDojo workspace/email scenario adapted into e2a email-native "
                        "detector benchmark; original benchmark measured agent task utility and attack success."
                    )
                man.write(json.dumps({
                    "id": tid,
                    "eml_path": f"dataset/prompt-injection/{OUT_EML}/{tid}.eml",
                    "label": {"is_malicious": True, "threat_type": tt,
                              "scenario": p.get("goal_type", "override"),
                              "injection_technique": p["technique"]},
                    "surface": SCHEMA_SURFACE[surface],
                    "detector_input": {"from": _sender(p), "subject": _subject(p)},
                    "provenance": {"source": source, "synthetic": True,
                                   "source_id": p.get("source_id") or p["id"],
                                   "base_payload_id": p["id"],
                                   **({"base_scenario_id": p["base_scenario_id"]}
                                      if p.get("base_scenario_id") else {})},
                    "sender_auth_condition": auth,
                    "split": "test" if p["source"] in {"llmail-inject", "agentdojo"} else "synthetic",
                    **({"source_metadata": p["source_metadata"]} if p.get("source_metadata") else {}),
                    **({"notes": notes} if notes else {}),
                }) + "\n")
                n += 1
    print(f"rendered {n} PI .eml ({len(payloads)} payloads x {len(SURFACES)} surfaces) -> {OUT_EML}/ + {OUT_MANIFEST}")
    print(f"  direct={direct} indirect={indirect}")


if __name__ == "__main__":
    main()

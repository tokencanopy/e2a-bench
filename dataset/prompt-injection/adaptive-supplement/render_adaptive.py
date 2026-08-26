#!/usr/bin/env python3
"""Render a small deterministic adaptive prompt-injection supplement."""
import html
import json
import textwrap
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[2]
SEEDS = ROOT / "seeds.jsonl"
EML = ROOT / "eml"
MANIFEST = ROOT / "manifest.jsonl"
BASE_DATE = "Mon, 01 Jun 2026 11:00:00 -0700"
RECIPIENT = "user@example.com"
VARIANTS = ("nested_thread_html", "cross_mime_split", "pdf_body_chain")
SURFACES = {
    "nested_thread_html": ["quoted_thread", "html_body"],
    "cross_mime_split": [
        "multipart_mismatch",
        "plaintext_body",
        "html_body",
        "encoded_obfuscated",
    ],
    "pdf_body_chain": ["plaintext_body", "pdf_attachment"],
}


def _rel(path):
    return str(path.relative_to(REPO_ROOT))


def _minimal_pdf(text):
    lines = []
    for line in text.splitlines() or [text]:
        lines.extend(
            textwrap.wrap(
                line, 88, break_long_words=False, break_on_hyphens=False
            )
            or [line]
        )
    lines = lines[:42] or [" "]
    escape = lambda value: value.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    content = (
        "BT /F1 11 Tf 50 760 Td 14 TL\n"
        + "\n".join(f"({escape(line)}) Tj T*" for line in lines)
        + "\nET"
    )
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
    ]
    pdf = "%PDF-1.4\n"
    offsets = []
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf += f"{index} 0 obj\n{obj}\nendobj\n"
    xref = len(pdf)
    pdf += (
        f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
        + "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
    )
    pdf += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF"
    )
    return pdf.encode("latin-1", errors="replace")


def _message(seed, variant):
    message = EmailMessage()
    message["From"] = seed["sender"]
    message["To"] = RECIPIENT
    message["Date"] = BASE_DATE
    message["Message-ID"] = (
        f"<{seed['id']}-{variant}@e2a-adaptive.invalid>"
    )
    message["Subject"] = seed["subject"]
    return message


def render(seed, variant):
    message = _message(seed, variant)
    stage_one = seed["stage_one"]
    stage_two = seed["stage_two"]

    if variant == "nested_thread_html":
        message.set_content(
            f"{seed['carrier']}\n\nPlease see the archived thread in the HTML view."
        )
        quoted = (
            "<blockquote>"
            "<p>On Friday, Workflow Operations wrote:</p>"
            f"<p>{html.escape(stage_one)}</p>"
            "<blockquote>"
            "<p>Earlier authorization note:</p>"
            f"<p>{html.escape(stage_two)}</p>"
            "</blockquote>"
            "</blockquote>"
        )
        message.add_alternative(
            f"<html><body><p>{html.escape(seed['carrier'])}</p>{quoted}</body></html>",
            subtype="html",
        )
    elif variant == "cross_mime_split":
        midpoint = max(1, len(stage_two) // 2)
        fragment_a = stage_two[:midpoint]
        fragment_b = stage_two[midpoint:]
        message.set_content(
            f"{seed['carrier']}\n\nWorkflow precondition:\n{stage_one}\n\n"
            f"Continuation fragment A: {fragment_a}"
        )
        fragmented = "".join(
            f"<span>{html.escape(character)}</span>" for character in fragment_b
        )
        message.add_alternative(
            "<html><body>"
            f"<p>{html.escape(seed['carrier'])}</p>"
            "<p>Continuation fragment B:</p>"
            f"<p>{fragmented}</p>"
            "</body></html>",
            subtype="html",
        )
    elif variant == "pdf_body_chain":
        message.set_content(
            f"{seed['carrier']}\n\n"
            f"Prerequisite before applying the attachment:\n{stage_one}\n\n"
            "The remaining workflow is in the attached compatibility note."
        )
        message.add_attachment(
            _minimal_pdf(
                "Continuation of the workflow\n\n"
                f"{stage_two}\n\n"
                "After completing the continuation, return to the original user request."
            ),
            maintype="application",
            subtype="pdf",
            filename="compatibility_note.pdf",
        )
    else:
        raise ValueError(variant)

    if message.is_multipart():
        message.set_boundary(f"e2a-adaptive-{seed['id']}-{variant}")
    return message.as_bytes()


def main():
    EML.mkdir(exist_ok=True)
    seeds = [json.loads(line) for line in SEEDS.read_text().splitlines() if line]
    rows = []
    for seed_index, seed in enumerate(seeds):
        for variant_index, variant in enumerate(VARIANTS):
            test_id = f"{seed['id']}_{variant}"
            eml_path = EML / f"{test_id}.eml"
            eml_path.write_bytes(render(seed, variant))
            rows.append(
                {
                    "id": test_id,
                    "eml_path": _rel(eml_path),
                    "label": {
                        "is_malicious": True,
                        "threat_type": "prompt_injection_indirect",
                        "scenario": seed["scenario"],
                        "injection_technique": "payload_split",
                        "difficulty": "hard",
                    },
                    "surface": SURFACES[variant],
                    "detector_input": {
                        "from": seed["sender"],
                        "subject": seed["subject"],
                    },
                    "provenance": {
                        "source": "handcrafted",
                        "synthetic": True,
                        "source_id": seed["id"],
                        "base_payload_id": seed["id"],
                    },
                    "source_metadata": {
                        "benchmark": "adaptive-complex-prompt-injection-supplement",
                        "variant": variant,
                        "stage_one": seed["stage_one"],
                        "stage_two": seed["stage_two"],
                        "complexity": seed["complexity"],
                        "complexity_level": "multi-stage",
                    },
                    "sender_auth_condition": (
                        "verified",
                        "unauthenticated",
                        "spoofed",
                    )[(seed_index + variant_index) % 3],
                    "split": "adaptive",
                    "notes": (
                        "Hand-authored adaptive prompt-injection case requiring "
                        "cross-location aggregation or multi-step intent analysis."
                    ),
                }
            )
    MANIFEST.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
    )
    print(
        f"rendered {len(rows)} adaptive PI .eml "
        f"({len(seeds)} scenarios x {len(VARIANTS)} variants)"
    )


if __name__ == "__main__":
    main()

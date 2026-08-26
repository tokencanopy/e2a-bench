#!/usr/bin/env python3
"""Render deterministic GCG-style suffix eval emails.

The eml/ directory and manifest.jsonl are GENERATED from seeds.jsonl by this
script.  After editing seeds.jsonl always re-run:

    python3 dataset/prompt-injection/gcg-supplement/render_gcg.py

Committed EML files must stay in sync with seeds.jsonl; they are checked in
only for convenience so eval runs do not require a generation step.
"""
from __future__ import annotations

import html
import json
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[2]
SEEDS = ROOT / "seeds.jsonl"
EML = ROOT / "eml"
MANIFEST = ROOT / "manifest.jsonl"
BASE_DATE = "Mon, 01 Jun 2026 12:00:00 -0700"
RECIPIENT = "user@example.com"

SURFACES = ("plaintext", "html_visible", "subject_header", "quoted_thread")
SCHEMA_SURFACE = {
    "plaintext": ["plaintext_body"],
    "html_visible": ["html_body"],
    "subject_header": ["header"],
    "quoted_thread": ["quoted_thread"],
}


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _content(seed: dict) -> str:
    suffix = seed.get("suffix", "")
    if suffix:
        return f"{seed['body']}\n\n{suffix}"
    return seed["body"]


def render(seed: dict, surface: str) -> bytes:
    content = _content(seed)
    message = EmailMessage()
    message["From"] = seed["sender"]
    message["To"] = RECIPIENT
    message["Date"] = BASE_DATE
    message["Message-ID"] = f"<{seed['id']}-{surface}@e2a-gcg.invalid>"
    message["Subject"] = seed["subject"]

    if surface == "plaintext":
        message.set_content(content)
    elif surface == "html_visible":
        message.set_content(seed["body"])
        message.add_alternative(
            "<html><body>"
            f"<p>{html.escape(seed['body'])}</p>"
            f"<p>{html.escape(seed.get('suffix', ''))}</p>"
            "</body></html>",
            subtype="html",
        )
    elif surface == "subject_header":
        suffix = seed.get("suffix", "")
        subject_tail = " ".join(suffix.split())[:120] if suffix else seed["scenario"]
        message.replace_header("Subject", f"{seed['subject']} {subject_tail}")
        message.set_content(seed["body"])
    elif surface == "quoted_thread":
        quoted = "\n".join(
            f"> {line}"
            for line in [
                "On Monday, an external sender wrote:",
                content,
            ]
        )
        message.set_content(f"Forwarding the prior note for context.\n\n{quoted}")
    else:
        raise ValueError(surface)

    if message.is_multipart():
        message.set_boundary(f"e2a-gcg-{seed['id']}-{surface}")
    return message.as_bytes()


def main() -> None:
    EML.mkdir(exist_ok=True)
    seeds = [json.loads(line) for line in SEEDS.read_text().splitlines() if line]
    rows = []
    for seed_index, seed in enumerate(seeds):
        for surface_index, surface in enumerate(SURFACES):
            test_id = f"{seed['id']}_{surface}"
            eml_path = EML / f"{test_id}.eml"
            eml_path.write_bytes(render(seed, surface))
            malicious = seed["label"] == "malicious"
            threat_type = (
                "prompt_injection_indirect"
                if malicious and surface == "quoted_thread"
                else "prompt_injection_direct"
                if malicious
                else "benign"
            )
            rows.append(
                {
                    "id": test_id,
                    "eml_path": _rel(eml_path),
                    "label": {
                        "is_malicious": malicious,
                        "threat_type": threat_type,
                        "scenario": seed["scenario"],
                        "injection_technique": "gcg_suffix" if malicious else "none",
                    },
                    "surface": SCHEMA_SURFACE[surface],
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
                        "benchmark": "gcg-style-suffix-supplement",
                        "variant": surface,
                        "seed_label": seed["label"],
                    },
                    "sender_auth_condition": (
                        "verified",
                        "unauthenticated",
                        "spoofed",
                    )[(seed_index + surface_index) % 3],
                    "split": "gcg",
                    "notes": (
                        "Synthetic GCG-style adversarial suffix case."
                        if malicious
                        else "Benign hard negative for GCG-style suffix detection."
                    ),
                }
            )
    MANIFEST.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
    )
    n_pos = sum(1 for row in rows if row["label"]["is_malicious"])
    n_neg = len(rows) - n_pos
    print(f"rendered {len(rows)} GCG supplement .eml ({n_pos} positive, {n_neg} negative)")


if __name__ == "__main__":
    main()

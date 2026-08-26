#!/usr/bin/env python3
"""Render HuggingFace real-GCG suffix seeds into plaintext EML files.

Generated files:
  eml/*.eml
  manifest.jsonl

Re-run after changing seeds.jsonl:
  python3 dataset/prompt-injection/gcg-supplement/hf-gcg/render_hf_gcg.py
"""
from __future__ import annotations

import json
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[3]
SEEDS = ROOT / "seeds.jsonl"
EML = ROOT / "eml"
MANIFEST = ROOT / "manifest.jsonl"
BASE_DATE = "Mon, 01 Jun 2026 13:00:00 -0700"
RECIPIENT = "user@example.com"


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def render(seed: dict) -> bytes:
    body = f"{seed['body'].strip()}\n\n{seed['suffix'].strip()}"
    message = EmailMessage()
    message["From"] = seed["sender"]
    message["To"] = RECIPIENT
    message["Date"] = BASE_DATE
    message["Message-ID"] = f"<{seed['id']}@e2a-hf-gcg.invalid>"
    message["Subject"] = seed["subject"]
    message.set_content(body)
    return message.as_bytes()


def main() -> None:
    if not SEEDS.exists():
        raise SystemExit(
            f"{SEEDS} not found. Run fetch_hf_gcg.py before rendering."
        )
    EML.mkdir(exist_ok=True)
    for old in EML.glob("*.eml"):
        old.unlink()
    seeds = [
        json.loads(line)
        for line in SEEDS.read_text().splitlines()
        if line.strip()
    ]
    rows = []
    for seed in seeds:
        eml_path = EML / f"{seed['id']}_plaintext.eml"
        eml_path.write_bytes(render(seed))
        rows.append({
            "id": f"{seed['id']}_plaintext",
            "eml_path": _rel(eml_path),
            "label": {
                "is_malicious": True,
                "threat_type": "prompt_injection_direct",
                "scenario": seed.get("scenario", "real_gcg_hf_suffix"),
                "injection_technique": "real_gcg_perplexity_suffix",
            },
            "surface": ["plaintext_body"],
            "detector_input": {
                "from": seed["sender"],
                "subject": seed["subject"],
            },
            "provenance": {
                "source": seed["source"],
                "synthetic": False,
                "license": seed.get("license", "MIT"),
                "source_url": seed.get("source_url", ""),
                "source_config": seed.get("source_config", ""),
                "source_split": seed.get("source_split", ""),
                "source_row_index": seed.get("source_row_index"),
                "source_model": seed.get("source_model", "unknown"),
                "source_id": seed["id"],
                "base_payload_id": seed["id"],
                "original_hash": seed.get("original_hash", ""),
                "note": (
                    "Real GCG suffix sampled from MatanBT/gcg-evaluated-data. "
                    "Email bodies are synthetic innocuous wrappers."
                ),
            },
            "source_metadata": {
                "benchmark": "hf-gcg-evaluated-data",
                "variant": "plaintext",
                "suffix_optimizer": seed.get("suffix_optimizer", "gcg"),
                "response_category": seed.get("response_category", ""),
                "strongreject_finetuned": seed.get("strongreject_finetuned", 0.0),
            },
            "sender_auth_condition": "unauthenticated",
            "split": "real_gcg_hf",
            "notes": (
                "Real GCG suffix challenge from HuggingFace "
                "MatanBT/gcg-evaluated-data."
            ),
        })

    MANIFEST.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
    )
    print(f"rendered {len(rows)} HuggingFace real GCG .eml files")
    print(f"wrote manifest -> {MANIFEST}")


if __name__ == "__main__":
    main()

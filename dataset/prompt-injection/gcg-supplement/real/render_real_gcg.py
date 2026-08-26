#!/usr/bin/env python3
"""Render real GCG-suffix eval emails from JailbreakBench (MIT license).

The suffix strings in seeds.jsonl are real GCG-optimized adversarial suffixes
taken from JailbreakBench/artifacts (vicuna-13b-v1.5 white-box attacks).

Source: https://github.com/JailbreakBench/artifacts/tree/main/attack-artifacts/GCG
License: MIT

Each suffix is paired with an innocuous business email body (NOT the original
harmful JailbreakBench goal) so the corpus tests whether the suffix alone
triggers detection, independent of the semantic content of the body.

These emails form a CHALLENGE SET: the gcg_suffix detector currently misses
them all (0% recall) because they contain mixed alphabetic+symbol content
rather than pure symbol-heavy patterns. See eval/detectors/gcg_suffix.py
for the documented limitation.

Re-run this script whenever seeds.jsonl changes:

    python3 dataset/prompt-injection/gcg-supplement/real/render_real_gcg.py
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
BASE_DATE = "Mon, 01 Jun 2026 12:00:00 -0700"
RECIPIENT = "user@example.com"


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def render(seed: dict) -> bytes:
    body = f"{seed['body']}\n\n{seed['suffix']}"
    message = EmailMessage()
    message["From"] = seed["sender"]
    message["To"] = RECIPIENT
    message["Date"] = BASE_DATE
    message["Message-ID"] = f"<{seed['id']}@e2a-real-gcg.invalid>"
    message["Subject"] = seed["subject"]
    message.set_content(body)
    return message.as_bytes()


def main() -> None:
    EML.mkdir(exist_ok=True)
    seeds = [json.loads(line) for line in SEEDS.read_text().splitlines() if line.strip()]
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
                "scenario": seed["scenario"],
                "injection_technique": "real_gcg_suffix",
            },
            "surface": ["plaintext_body"],
            "detector_input": {
                "from": seed["sender"],
                "subject": seed["subject"],
            },
            "provenance": {
                "source": seed["source"],
                "synthetic": False,
                "license": seed["license"],
                "source_model": seed["source_model"],
                "original_index": seed["original_index"],
                "source_id": seed["id"],
                "base_payload_id": seed["id"],
                "note": (
                    "Real GCG suffix from JailbreakBench/artifacts. "
                    "Suffix strings are MIT licensed. "
                    "Email bodies are synthetic innocuous wrappers."
                ),
            },
            "source_metadata": {
                "benchmark": "jailbreakbench-gcg-real",
                "source_url": "https://github.com/JailbreakBench/artifacts",
                "variant": "plaintext",
            },
            "sender_auth_condition": "unauthenticated",
            "split": "real_gcg",
            "notes": (
                "CHALLENGE SET: gcg_suffix detector currently misses these (0% recall). "
                "Mixed alpha+symbol GCG suffixes require a perplexity-based signal "
                "beyond this heuristic detector's scope."
            ),
        })

    MANIFEST.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
    )
    print(f"rendered {len(rows)} real GCG .eml (all positive/malicious)")
    print(f"NOTE: These are a CHALLENGE SET. Detector currently misses all of them.")
    print(f"      Run eval/run_eval.py --detectors gcg_suffix and check the real_gcg split.")


if __name__ == "__main__":
    main()

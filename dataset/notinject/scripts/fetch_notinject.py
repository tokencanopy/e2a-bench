#!/usr/bin/env python3
"""fetch_notinject.py — download the NotInject benign over-defense dataset and
render each sample as a plaintext .eml for use in the e2a eval harness.

Source: leolee99/NotInject on HuggingFace (MIT)
Paper:  InjecGuard — https://arxiv.org/abs/2410.22770

NotInject has 339 benign text samples (113 × 3 subsets by trigger-word count)
that contain injection trigger words ("ignore", "instructions", etc.) in legitimate
context. They are used to measure *over-defense* — how often a detector wrongly
flags benign content because it contains alarm-word surface patterns.

We wrap each sample in a minimal plaintext RFC-2822 email so the same eval
harness that runs on PI and ham entries can run on these.

Usage:
    cd e2a-bench
    python3 dataset/notinject/scripts/fetch_notinject.py
"""
from __future__ import annotations

import email.utils
import hashlib
import json
import os
import re
import sys
import textwrap

# ---------------------------------------------------------------------------
# Realistic sender pool — benign corporate / personal senders
# ---------------------------------------------------------------------------
_SENDERS = [
    ("Jordan Hayes", "j.hayes@acmecorp.example.com"),
    ("Sam Rivera", "srivera@techstartup.example.io"),
    ("Alex Kim", "alexkim@university.example.edu"),
    ("Morgan Lee", "morgan.lee@consulting.example.com"),
    ("Casey Thompson", "cthompson@nonprofit.example.org"),
    ("Riley Nguyen", "riley.n@freelance.example.net"),
    ("Taylor Brooks", "tbrooks@healthcare.example.com"),
    ("Jamie Patel", "j.patel@finance.example.com"),
]

# Category → subject templates so emails look plausible
_SUBJECT_TEMPLATES = {
    "Common Queries":    ["Quick question", "Following up", "Checking in",
                          "A few thoughts", "Your input needed"],
    "Technique Queries": ["Technical clarification", "Process question",
                          "How-to help", "Workflow question"],
    "Virtual Creation":  ["Creative project", "Draft feedback needed",
                          "Content request", "Writing assistance"],
    "Multilingual Queries": ["Question (bilingual)", "Multi-language note",
                             "Language assistance"],
}
_SUBJECT_DEFAULT = ["Quick question", "Following up", "Your thoughts?"]


def _sender_for(idx: int) -> tuple[str, str]:
    return _SENDERS[idx % len(_SENDERS)]


def _subject_for(category: str, idx: int) -> str:
    templates = _SUBJECT_TEMPLATES.get(category, _SUBJECT_DEFAULT)
    return templates[idx % len(templates)]


def _render_eml(
    from_name: str,
    from_addr: str,
    subject: str,
    body: str,
) -> bytes:
    """Build a minimal RFC-2822 plaintext email."""
    # Wrap long lines at 76 chars — standard email convention
    wrapped = textwrap.fill(body, width=76, break_long_words=False,
                            break_on_hyphens=False)
    parts = [
        f"From: {from_name} <{from_addr}>",
        f"To: agent@e2a.example.com",
        f"Subject: {subject}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 7bit",
        "",
        wrapped,
    ]
    return "\r\n".join(parts).encode("utf-8")


def _stable_id(prompt: str, idx: int) -> str:
    h = hashlib.sha256(prompt.encode()).hexdigest()[:8]
    return f"notinject_{idx:04d}_{h}"


def fetch_and_render(base_dir: str = ".") -> None:
    eml_dir = os.path.join(base_dir, "dataset/notinject/eml")
    out_manifest = os.path.join(base_dir, "dataset/notinject/manifest.jsonl")
    os.makedirs(eml_dir, exist_ok=True)

    # -----------------------------------------------------------------------
    # Load from HuggingFace datasets library
    # -----------------------------------------------------------------------
    try:
        from datasets import load_dataset  # type: ignore
    except ImportError:
        sys.exit(
            "datasets library not found.\n"
            "Install with: pip install datasets pyarrow"
        )

    print("Downloading leolee99/NotInject from HuggingFace…")
    ds = load_dataset("leolee99/NotInject", trust_remote_code=False)

    # Collect all splits into a flat list, preserving subset metadata
    rows: list[dict] = []
    for split_name, split_ds in ds.items():
        # split_name is e.g. "NotInject_one", "NotInject_two", "NotInject_three"
        n_triggers = {"NotInject_one": 1, "NotInject_two": 2,
                      "NotInject_three": 3}.get(split_name, 0)
        for row in split_ds:
            rows.append({
                "prompt": row["prompt"],
                "word_list": list(row.get("word_list") or []),
                "category": row.get("category", ""),
                "subset": split_name,
                "n_trigger_words": n_triggers,
            })

    print(f"  loaded {len(rows)} samples across {len(ds)} subsets")

    manifest_entries: list[dict] = []
    for idx, row in enumerate(rows):
        prompt = row["prompt"].strip()
        category = row["category"]
        name, addr = _sender_for(idx)
        subject = _subject_for(category, idx)
        eml_bytes = _render_eml(name, addr, subject, prompt)

        entry_id = _stable_id(prompt, idx)
        rel_path = f"dataset/notinject/eml/{entry_id}.eml"
        abs_path = os.path.join(base_dir, rel_path)

        with open(abs_path, "wb") as f:
            f.write(eml_bytes)

        manifest_entries.append({
            "id": entry_id,
            "eml_path": rel_path,
            "label": {
                "is_malicious": False,
                "threat_type": "benign",
                "category": "over_defense_trigger",
            },
            "surface": ["plaintext_body"],
            "detector_input": {
                "from": f"{name} <{addr}>",
                "subject": subject,
                "body": {"text": prompt, "html": None},
            },
            "provenance": {
                "source": "notinject",
                "synthetic": False,
                "source_id": entry_id,
                "subset": row["subset"],
                "n_trigger_words": row["n_trigger_words"],
                "trigger_words": row["word_list"],
                "notinject_category": category,
            },
            "sender_auth_condition": "verified",
            "split": "test",
        })

    with open(out_manifest, "w") as f:
        for entry in manifest_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"  wrote {len(manifest_entries)} .eml files → {eml_dir}/")
    print(f"  wrote manifest → {out_manifest}")

    # Summary
    from collections import Counter
    cats = Counter(e["provenance"]["notinject_category"] for e in manifest_entries)
    subsets = Counter(e["provenance"]["subset"] for e in manifest_entries)
    print("\nBy category:")
    for k, v in sorted(cats.items()):
        print(f"  {k}: {v}")
    print("\nBy subset (trigger-word count):")
    for k, v in sorted(subsets.items()):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", default=".",
                        help="repo root (default: cwd)")
    args = parser.parse_args()
    fetch_and_render(os.path.abspath(args.base_dir))

#!/usr/bin/env python3
"""Merge PI positives with matched benign, ham, and NotInject negatives.

The combined manifest lets detectors see both positive (PI) and negative (ham +
NotInject) examples in a single pass so FPR can be computed alongside TPR.

Negative sources:
  --pi-benign-manifest  Structurally matched PI benign controls (default)
  --ham-manifest        SpamAssassin benign + phishing non-PI controls (default)
  --notinject-manifest  NotInject benign over-defense trigger samples (optional)

Additional positives:
  --adaptive-manifest  Small adaptive complex PI supplement (auto-included)

Usage:
    python3 eval/combine_manifests.py [--out eval/combined_manifest.jsonl]
    python3 eval/combine_manifests.py --notinject-manifest dataset/notinject/manifest.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pi-manifest",
        default="dataset/prompt-injection/manifest.jsonl",
        help="PI manifest (positives)",
    )
    parser.add_argument(
        "--ham-manifest",
        default="dataset/phishing/manifest.jsonl",
        help="Ham manifest (negatives)",
    )
    parser.add_argument(
        "--pi-benign-manifest",
        default="dataset/prompt-injection/benign/manifest.jsonl",
        help="Structurally matched prompt-injection benign controls",
    )
    parser.add_argument(
        "--adaptive-manifest",
        default="dataset/prompt-injection/adaptive-supplement/manifest.jsonl",
        help="Adaptive complex PI supplement (auto-included if present)",
    )
    parser.add_argument(
        "--no-adaptive",
        action="store_true",
        help="Exclude the adaptive complex PI supplement",
    )
    parser.add_argument(
        "--notinject-manifest",
        default=None,
        help="NotInject over-defense manifest (optional; default: auto-include if present)",
    )
    parser.add_argument(
        "--no-notinject",
        action="store_true",
        help="Exclude NotInject even if dataset/notinject/manifest.jsonl exists",
    )
    parser.add_argument(
        "--out",
        default="eval/combined_manifest.jsonl",
        help="output path",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="root for resolving manifest paths (default: cwd)",
    )
    args = parser.parse_args()

    base = os.path.abspath(args.base_dir)
    pi_path = os.path.join(base, args.pi_manifest)
    adaptive_path = os.path.join(base, args.adaptive_manifest)
    ham_path = os.path.join(base, args.ham_manifest)
    pi_benign_path = os.path.join(base, args.pi_benign_manifest)
    out_path = os.path.join(base, args.out)

    # Auto-include NotInject if it exists unless --no-notinject is set
    notinject_path: str | None = None
    if not args.no_notinject:
        candidate = args.notinject_manifest or os.path.join(
            base, "dataset/notinject/manifest.jsonl"
        )
        if os.path.exists(candidate):
            notinject_path = candidate

    PI_THREAT_TYPES = {"prompt_injection_direct", "prompt_injection_indirect"}
    # The paper's phishing-family population is 1,000 Nazario phishing records
    # plus 500 SpamAssassin spam records. Preserve the distinct threat_type but
    # give all 1,500 records the same positive evaluation role.
    PHISHING_THREAT_TYPES = {"phishing", "scam", "spam"}

    neg_paths = [p for p in [pi_benign_path, ham_path, notinject_path] if p]
    positive_paths = [pi_path]
    if not args.no_adaptive and os.path.exists(adaptive_path):
        positive_paths.append(adaptive_path)
    entries: list[dict] = []
    seen_ids: set[str] = set()
    skipped_no_eml: int = 0
    for path in positive_paths + neg_paths:
        if not os.path.exists(path):
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                # piguard requires eml_path (it feeds raw RFC822 bytes to the Go binary).
                # CSV-sourced entries (Enron, Nazario_5, Ling) have no .eml file and use
                # inline detector_input instead. Skip them here; they are handled by the
                # phishing-specific eval pipeline (run_eval.py with phishing manifests).
                if "eml_path" not in entry:
                    skipped_no_eml += 1
                    continue
                # Tag each record with its evaluation role for task-aware grading.
                # is_malicious is left as the record's OWN ground truth (PI and
                # phishing are both malicious in reality); the PI-vs-phishing-vs-
                # benign split is carried by eval_role so grade.py can scope each
                # task and keep phishing out of the PI false-positive denominator.
                #   pi_positive -> prompt-injection attacks (Track A positives)
                #   phishing    -> phishing/scam lures (Track B positives; excluded
                #                  from Track A, used in the cross-fire diagnostic)
                #   negative    -> genuinely benign mail (ham, NotInject, pi-benign)
                tt = entry["label"].get("threat_type", "")
                if tt in PI_THREAT_TYPES:
                    entry["eval_role"] = "pi_positive"
                elif tt in PHISHING_THREAT_TYPES:
                    entry["eval_role"] = "phishing"
                else:
                    entry["eval_role"] = "negative"
                if entry["id"] in seen_ids:
                    sys.exit(f"error: duplicate id {entry['id']!r} (in {path}); ids "
                             "must be unique across sources — grading keys by id, so a "
                             "collision silently drops a record.")
                seen_ids.add(entry["id"])
                entries.append(entry)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")

    roles: dict[str, int] = {}
    for e in entries:
        roles[e["eval_role"]] = roles.get(e["eval_role"], 0) + 1
    role_summary = ", ".join(f"{r}={n}" for r, n in sorted(roles.items()))
    sources = {}
    for e in entries:
        src = e["provenance"]["source"]
        sources[src] = sources.get(src, 0) + 1
    src_summary = ", ".join(f"{s}={n}" for s, n in sorted(sources.items()))
    print(f"wrote {len(entries)} entries → {out_path}")
    print(f"  eval_role: {role_summary}")
    print(f"  sources: {src_summary}")
    if skipped_no_eml:
        print(f"  skipped {skipped_no_eml} CSV-sourced entries without eml_path (use phishing eval pipeline for those)")
    if os.path.exists(pi_benign_path):
        print(f"  pi-benign: included ({pi_benign_path})")
    else:
        print(f"  pi-benign: missing ({pi_benign_path})")
    if adaptive_path in positive_paths:
        print(f"  adaptive: included ({adaptive_path})")
    else:
        print("  adaptive: excluded")
    if notinject_path:
        print(f"  notinject: included ({notinject_path})")
    else:
        print("  notinject: excluded (pass --notinject-manifest or place at dataset/notinject/manifest.jsonl)")


if __name__ == "__main__":
    main()

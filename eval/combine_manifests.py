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

Additional mixed slice:
  --gcg-manifest       GCG-style suffix supplement with positives + hard negatives
  --real-gcg-manifest  JailbreakBench real GCG challenge positives
  --hf-gcg-manifest    HuggingFace real GCG challenge positives

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
        "--gcg-manifest",
        default="dataset/prompt-injection/gcg-supplement/manifest.jsonl",
        help="GCG-style suffix supplement (auto-included if present)",
    )
    parser.add_argument(
        "--real-gcg-manifest",
        default="dataset/prompt-injection/gcg-supplement/real/manifest.jsonl",
        help="Real GCG challenge supplement (auto-included if present)",
    )
    parser.add_argument(
        "--hf-gcg-manifest",
        default="dataset/prompt-injection/gcg-supplement/hf-gcg/manifest.jsonl",
        help="HuggingFace real GCG supplement (auto-included if present)",
    )
    parser.add_argument(
        "--no-gcg",
        action="store_true",
        help="Exclude GCG-style and real GCG supplements",
    )
    parser.add_argument(
        "--no-real-gcg",
        action="store_true",
        help="Exclude real GCG challenge supplements only",
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
    gcg_path = os.path.join(base, args.gcg_manifest)
    real_gcg_path = os.path.join(base, args.real_gcg_manifest)
    hf_gcg_path = os.path.join(base, args.hf_gcg_manifest)
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
    # "spam" is what the SpamAssassin spam split is stamped with; "scam" was the
    # name used by an earlier corpus revision. Both are phishing-task positives.
    PHISHING_THREAT_TYPES = {"phishing", "spam", "scam"}

    neg_paths = [p for p in [pi_benign_path, ham_path, notinject_path] if p]
    positive_paths = [pi_path]
    if not args.no_adaptive and os.path.exists(adaptive_path):
        positive_paths.append(adaptive_path)
    mixed_paths = []
    if not args.no_gcg and os.path.exists(gcg_path):
        mixed_paths.append(gcg_path)
    if not args.no_gcg and not args.no_real_gcg and os.path.exists(real_gcg_path):
        mixed_paths.append(real_gcg_path)
    if not args.no_gcg and not args.no_real_gcg and os.path.exists(hf_gcg_path):
        mixed_paths.append(hf_gcg_path)

    entries: list[dict] = []
    seen_ids: set[str] = set()
    skipped_no_eml: int = 0
    for path in positive_paths + mixed_paths + neg_paths:
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
    if gcg_path in mixed_paths:
        print(f"  gcg: included ({gcg_path})")
    else:
        print("  gcg: excluded")
    if real_gcg_path in mixed_paths:
        print(f"  real-gcg: included ({real_gcg_path})")
    else:
        print("  real-gcg: excluded")
    if hf_gcg_path in mixed_paths:
        print(f"  hf-gcg: included ({hf_gcg_path})")
    else:
        print("  hf-gcg: excluded")
    if notinject_path:
        print(f"  notinject: included ({notinject_path})")
    else:
        print("  notinject: excluded (pass --notinject-manifest or place at dataset/notinject/manifest.jsonl)")


if __name__ == "__main__":
    main()

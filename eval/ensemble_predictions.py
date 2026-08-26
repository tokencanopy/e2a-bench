#!/usr/bin/env python3
"""Combine phishing detector prediction JSONL files into one ensemble JSONL."""
from __future__ import annotations

import argparse
import json
import math
import os


def load_jsonl_by_id(path: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            out[rec["id"]] = rec
    return out


def load_manifest_ids(path: str | None) -> list[str] | None:
    if not path:
        return None
    ids: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                ids.append(json.loads(line)["id"])
    return ids


def usable_score(pred: dict | None) -> tuple[float | None, str | None]:
    if pred is None:
        return None, "missing"
    if pred.get("error"):
        return None, str(pred["error"])
    try:
        score = float(pred.get("score"))
    except (TypeError, ValueError):
        return None, "non-finite score"
    if not math.isfinite(score):
        return None, "non-finite score"
    return max(0.0, min(1.0, score)), None


def action_from_score(score: float) -> str:
    if score >= 0.75:
        return "block"
    if score >= 0.35:
        return "review"
    return "allow"


def combine_one(
    id_: str,
    local: dict | None,
    gemini: dict | None,
    threshold: float,
    detector_name: str,
    strategy: str = "max_score",
) -> dict:
    local_score, local_error = usable_score(local)
    gemini_score, gemini_error = usable_score(gemini)
    available = [s for s in (local_score, gemini_score) if s is not None]
    latency_ms = int((local or {}).get("latency_ms") or 0) + int(
        (gemini or {}).get("latency_ms") or 0
    )

    if not available:
        return {
            "id": id_,
            "detector": detector_name,
            "flagged": False,
            "score": 0.0,
            "action": "unknown",
            "categories": [],
            "latency_ms": latency_ms,
            "error": f"local={local_error}; gemini={gemini_error}",
        }

    if strategy == "gemini_primary":
        score = gemini_score if gemini_score is not None else local_score
    elif strategy == "mean_score":
        score = sum(available) / len(available)
    elif strategy == "consensus":
        score = min(available) if len(available) == 2 else available[0]
    else:
        score = max(available)

    return {
        "id": id_,
        "detector": detector_name,
        "flagged": score >= threshold,
        "score": score,
        "action": action_from_score(score),
        "categories": [{
            "name": "phishing_ensemble",
            "strategy": strategy,
            "local_score": local_score,
            "gemini_score": gemini_score,
            "local_error": local_error,
            "gemini_error": gemini_error,
            "threshold": threshold,
        }],
        "latency_ms": latency_ms,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Combine local phishing classifier + Gemini phishing predictions."
    )
    parser.add_argument("--local", required=True, help="local classifier prediction JSONL")
    parser.add_argument("--gemini", required=True, help="gemini-phishing prediction JSONL")
    parser.add_argument("--out", required=True, help="output ensemble JSONL")
    parser.add_argument("--manifest", default=None, help="optional manifest for id order/filter")
    parser.add_argument("--threshold", type=float, default=0.35)
    parser.add_argument("--detector-name", default="ensemble_phishing_tfidf_gemini")
    parser.add_argument(
        "--strategy",
        choices=["gemini_primary", "max_score", "mean_score", "consensus"],
        default="max_score",
        help="score combiner; max_score takes the higher of local and Gemini (plan default)",
    )
    args = parser.parse_args()

    local = load_jsonl_by_id(args.local)
    gemini = load_jsonl_by_id(args.gemini)
    manifest_ids = load_manifest_ids(args.manifest)
    ids = manifest_ids if manifest_ids is not None else sorted(set(local) | set(gemini))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        for id_ in ids:
            rec = combine_one(id_, local.get(id_), gemini.get(id_),
                              args.threshold, args.detector_name, args.strategy)
            f.write(json.dumps(rec) + "\n")

    print(f"wrote {len(ids)} ensemble predictions -> {args.out}")


if __name__ == "__main__":
    main()

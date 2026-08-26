#!/usr/bin/env python3
"""Calibrate gcg_perplexity score mapping against positive and negative manifests."""
from __future__ import annotations

import argparse
import json
import math
import os
import random
from pathlib import Path

from detectors.gcg_perplexity import (
    DEFAULT_MODEL,
    GCGPerplexityDetector,
)


def load_jsonl(path: str) -> list[dict]:
    if not path or not os.path.exists(path):
        return []
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def sample_rows(rows: list[dict], limit: int, seed: int) -> list[dict]:
    if limit <= 0 or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    return rng.sample(rows, limit)


def raw_score(pred: dict) -> float:
    for cat in pred.get("categories", []):
        if cat.get("native_code") == "tail_nll_delta":
            return float(cat.get("raw_score", 0.0))
    return 0.0


def logit(p: float) -> float:
    p = min(1 - 1e-6, max(1e-6, p))
    return math.log(p / (1 - p))


def threshold_at_fpr(pos: list[float], neg: list[float], target_fpr: float) -> tuple[float, float, float]:
    if not pos:
        return 0.0, 0.0, 0.0
    if not neg:
        threshold = min(pos)
        return threshold, 1.0, 0.0
    candidates = sorted(set(pos + neg), reverse=True)
    best = (max(candidates) + 1e-6, 0.0, 0.0)
    for threshold in candidates:
        fp = sum(score >= threshold for score in neg)
        fpr = fp / len(neg)
        if fpr <= target_fpr:
            recall = sum(score >= threshold for score in pos) / len(pos)
            if recall >= best[1]:
                best = (threshold, recall, fpr)
    return best


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--positive-manifest",
        action="append",
        default=None,
    )
    parser.add_argument(
        "--negative-manifest",
        action="append",
        default=None,
    )
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--out", default="eval/detectors/gcg_perplexity_thresholds.json")
    parser.add_argument("--max-positive", type=int, default=1000)
    parser.add_argument("--max-negative", type=int, default=1500)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20260626)
    args = parser.parse_args()

    positive_manifests = args.positive_manifest or [
        "dataset/prompt-injection/gcg-supplement/hf-gcg/manifest.jsonl",
        "dataset/prompt-injection/gcg-supplement/real/manifest.jsonl",
    ]
    negative_manifests = args.negative_manifest or [
        "dataset/prompt-injection/benign/manifest.jsonl",
        "dataset/notinject/manifest.jsonl",
        "dataset/prompt-injection/gcg-supplement/manifest.jsonl",
        "dataset/phishing/manifest.jsonl",
    ]

    positives = []
    for path in positive_manifests:
        positives.extend(
            row for row in load_jsonl(path)
            if row.get("label", {}).get("is_malicious")
        )
    negatives = []
    for path in negative_manifests:
        for row in load_jsonl(path):
            malicious = row.get("label", {}).get("is_malicious")
            threat_type = row.get("label", {}).get("threat_type", "")
            if not malicious or threat_type == "benign":
                negatives.append(row)

    positives = sample_rows(positives, args.max_positive, args.seed)
    negatives = sample_rows(negatives, args.max_negative, args.seed + 1)
    print(f"calibration rows: positives={len(positives)} negatives={len(negatives)}")

    detector = GCGPerplexityDetector(
        base_dir=args.base_dir,
        model_id=args.model,
        thresholds_path="",
        batch_size=args.batch_size,
    )

    def score_rows(rows: list[dict]) -> list[float]:
        scores: list[float] = []
        for start in range(0, len(rows), args.batch_size):
            for pred in detector.predict_batch(rows[start:start + args.batch_size]):
                if not pred.error:
                    scores.append(raw_score(pred.to_dict()))
        return scores

    pos_raw = score_rows(positives)
    neg_raw = score_rows(negatives)
    review_raw, review_recall, review_fpr = threshold_at_fpr(pos_raw, neg_raw, 0.01)
    block_raw, block_recall, block_fpr = threshold_at_fpr(pos_raw, neg_raw, 0.001)

    review_target = 0.35
    block_target = 0.75
    if block_raw > review_raw + 1e-6:
        scale = (block_raw - review_raw) / (logit(block_target) - logit(review_target))
        center = review_raw - scale * logit(review_target)
    else:
        scale = 0.65
        center = review_raw - scale * logit(review_target)

    out = {
        "model_id": args.model,
        "review_threshold": review_target,
        "block_threshold": block_target,
        "score_center": center,
        "score_scale": max(scale, 1e-6),
        "review_raw_threshold": review_raw,
        "block_raw_threshold": block_raw,
        "review_recall_at_calibration": review_recall,
        "review_fpr_at_calibration": review_fpr,
        "block_recall_at_calibration": block_recall,
        "block_fpr_at_calibration": block_fpr,
        "calibration_positive_n": len(pos_raw),
        "calibration_negative_n": len(neg_raw),
        "target_review_fpr": 0.01,
        "target_block_fpr": 0.001,
        "tail_windows": [24, 32, 48, 64],
        "prefix_window": 64,
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()

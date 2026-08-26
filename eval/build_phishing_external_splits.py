#!/usr/bin/env python3
"""Build reproducible external phishing-training splits.

This script keeps the locked MeAJOR test separate from the small TREC7
adaptation sample and keeps Ling commercial spam hard-negative test samples out
of training.  It expects EmailRecord JSONL manifests, not raw CSVs.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def content_hash(entry: dict) -> str:
    di = entry.get("detector_input", {})
    subject = (di.get("subject") or "").strip()
    body = (((di.get("body") or {}).get("text")) or "").strip()
    raw = f"{subject}\x00{body}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def dedupe(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for row in rows:
        h = content_hash(row)
        if h in seen:
            continue
        seen.add(h)
        out.append(row)
    return out


def count(rows: list[dict]) -> dict[str, int]:
    return dict(collections.Counter(r.get("label", {}).get("threat_type", "") for r in rows))


def shuffled_sample(pool: list[dict], n: int, rng: random.Random) -> tuple[list[dict], list[dict]]:
    pool = list(pool)
    rng.shuffle(pool)
    return pool[:n], pool[n:]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-manifest", default="dataset/phishing/manifest.jsonl")
    parser.add_argument("--meajor-manifest", required=True)
    parser.add_argument("--ling-manifest", default="dataset/phishing/ood_ling_manifest.jsonl")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--seed", type=int, default=127)
    parser.add_argument("--source-dev-per-class", type=int, default=3000)
    parser.add_argument("--trec7-adapt-per-class", type=int, default=2500)
    parser.add_argument("--trec7-dev-per-class", type=int, default=1000)
    parser.add_argument("--ling-spam-train", type=int, default=350)
    parser.add_argument("--ling-spam-dev", type=int, default=50)
    parser.add_argument("--ling-benign-train", type=int, default=1600)
    parser.add_argument("--ling-benign-dev", type=int, default=300)
    parser.add_argument("--ling-spam-repeat", type=int, default=8)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    out_dir = Path(args.out_dir)
    base = load_jsonl(Path(args.base_manifest))
    meajor = dedupe(load_jsonl(Path(args.meajor_manifest)))
    ling = dedupe(load_jsonl(Path(args.ling_manifest)))

    by_source: dict[str, list[dict]] = collections.defaultdict(list)
    for row in meajor:
        by_source[row.get("provenance", {}).get("source", "")].append(row)

    known_sources = {
        "meajor_zenodo_trec5", "meajor_zenodo_trec6", "meajor_zenodo_trec7",
    }
    present = set(by_source) & known_sources
    if not present:
        raise SystemExit(
            f"meajor manifest contains no entries with expected provenance.source values "
            f"({sorted(known_sources)}). Got sources: {sorted(set(by_source))}.\n"
            "Run ingest_zenodo.py add-meajor <MeAJOR_csv> to ingest MeAJOR data first."
        )

    source_pool = by_source["meajor_zenodo_trec5"] + by_source["meajor_zenodo_trec6"]
    source_pos = [r for r in source_pool if r.get("label", {}).get("threat_type") == "phishing"]
    source_neg = [r for r in source_pool if r.get("label", {}).get("threat_type") == "benign"]
    source_dev_pos, source_train_pos = shuffled_sample(source_pos, args.source_dev_per_class, rng)
    source_dev_neg, source_train_neg = shuffled_sample(source_neg, args.source_dev_per_class, rng)
    source_train = source_train_pos + source_train_neg
    source_dev = source_dev_pos + source_dev_neg
    trec7 = by_source["meajor_zenodo_trec7"]
    trec7_pos = [r for r in trec7 if r.get("label", {}).get("threat_type") == "phishing"]
    trec7_neg = [r for r in trec7 if r.get("label", {}).get("threat_type") == "benign"]
    if len(trec7_pos) < args.trec7_adapt_per_class + args.trec7_dev_per_class + 1:
        raise SystemExit(
            f"meajor_zenodo_trec7 has only {len(trec7_pos)} positives, need at least "
            f"{args.trec7_adapt_per_class + args.trec7_dev_per_class + 1} "
            f"(--trec7-adapt-per-class + --trec7-dev-per-class + 1 for test)."
        )
    if len(trec7_neg) < args.trec7_adapt_per_class + args.trec7_dev_per_class + 1:
        raise SystemExit(
            f"meajor_zenodo_trec7 has only {len(trec7_neg)} negatives, need at least "
            f"{args.trec7_adapt_per_class + args.trec7_dev_per_class + 1}."
        )
    t7_train_pos, trec7_pos = shuffled_sample(trec7_pos, args.trec7_adapt_per_class, rng)
    t7_train_neg, trec7_neg = shuffled_sample(trec7_neg, args.trec7_adapt_per_class, rng)
    t7_dev_pos, t7_test_pos = shuffled_sample(trec7_pos, args.trec7_dev_per_class, rng)
    t7_dev_neg, t7_test_neg = shuffled_sample(trec7_neg, args.trec7_dev_per_class, rng)

    trec7_adapt_train = t7_train_pos + t7_train_neg
    trec7_adapt_dev = t7_dev_pos + t7_dev_neg
    trec7_adapt_test = t7_test_pos + t7_test_neg

    ling_spam = [r for r in ling if r.get("label", {}).get("threat_type") == "spam"]
    ling_benign = [r for r in ling if r.get("label", {}).get("threat_type") == "benign"]
    ling_train_spam, ling_spam = shuffled_sample(ling_spam, args.ling_spam_train, rng)
    ling_dev_spam, ling_test_spam = shuffled_sample(ling_spam, args.ling_spam_dev, rng)
    ling_train_benign, ling_benign = shuffled_sample(ling_benign, args.ling_benign_train, rng)
    ling_dev_benign, ling_test_benign = shuffled_sample(ling_benign, args.ling_benign_dev, rng)
    ling_hard_train = (ling_train_spam * args.ling_spam_repeat) + ling_train_benign
    ling_hard_dev = ling_dev_spam + ling_dev_benign
    ling_hard_test = ling_test_spam + ling_test_benign

    combined_train = base + source_train + trec7_adapt_train + ling_hard_train
    combined_dev = trec7_adapt_dev + ling_hard_dev

    outputs = {
        "meajor_source_train.jsonl": source_train,
        "meajor_source_dev.jsonl": source_dev,
        "meajor_trec7_adapt_train.jsonl": trec7_adapt_train,
        "meajor_trec7_adapt_dev.jsonl": trec7_adapt_dev,
        "meajor_trec7_adapt_test.jsonl": trec7_adapt_test,
        "ling_hard_train_up.jsonl": ling_hard_train,
        "ling_hard_dev_up.jsonl": ling_hard_dev,
        "ling_hard_test_up.jsonl": ling_hard_test,
        "combined_adapt_ling_train_up.jsonl": combined_train,
        "combined_adapt_ling_dev_up.jsonl": combined_dev,
    }
    for filename, rows in outputs.items():
        rng.shuffle(rows)
        path = out_dir / filename
        write_jsonl(path, rows)
        print(f"{filename}: n={len(rows)} labels={count(rows)}")


if __name__ == "__main__":
    main()

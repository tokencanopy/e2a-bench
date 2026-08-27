#!/usr/bin/env python3
"""grade.py — compute detection metrics from a run directory.

Reads <run-dir>/manifest_used.jsonl (ground truth) and <run-dir>/<detector>.jsonl
(predictions) for each detector found in the run directory.

Outputs:
  <run-dir>/metrics.json   — machine-readable metrics
  stdout                   — human-readable summary table

Usage:
    python3 eval/grade.py --run-dir eval/runs/latest
    python3 eval/grade.py --run-dir eval/runs/latest --slice surface
    python3 eval/grade.py --run-dir eval/runs/latest --slice threat_type
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)


def tpr_at_fpr(
    labels: list[int],
    scores: list[float],
    fpr_targets: tuple[float, ...] = (0.01, 0.001),
) -> dict[float, float]:
    """TPR at the highest operating point whose FPR stays <= each target.

    The deployable catch rate for an imbalanced gateway: pin the false-alarm
    budget (most mail is benign), then ask how many threats are caught within
    it. Needs both classes present; returns nan per target otherwise.
    """
    if len(set(labels)) < 2:
        return {t: float("nan") for t in fpr_targets}
    n_neg = sum(1 for y in labels if y == 0)
    try:
        fpr_arr, tpr_arr, _ = roc_curve(labels, scores)
    except ValueError:
        # non-finite scores etc. — caller should sanitize, but never crash the run.
        return {t: float("nan") for t in fpr_targets}
    out: dict[float, float] = {}
    for t in fpr_targets:
        # Granularity floor: the smallest representable non-zero FPR is 1/n_neg.
        # A target below it would silently collapse to TPR@0%FPR and be reported as
        # a confident number — return nan instead so an under-powered negative set
        # is visible rather than misleading.
        if n_neg == 0 or t < 1.0 / n_neg:
            out[t] = float("nan")
            continue
        mask = fpr_arr <= t
        out[t] = float(tpr_arr[mask].max()) if mask.any() else 0.0
    return out


def load_manifest(path: str) -> dict[str, dict]:
    """Returns id → entry mapping."""
    m: dict[str, dict] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entry = json.loads(line)
                m[entry["id"]] = entry
    return m


def load_predictions(path: str) -> dict[str, dict]:
    """Returns id → prediction mapping."""
    p: dict[str, dict] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                pred = json.loads(line)
                p[pred["id"]] = pred
    return p


def _score_or_none(pred: dict) -> float | None:
    """Finite score from a prediction, or None for missing/non-finite.

    A missing or NaN/Inf score must NOT be coerced to 0.0 (a confident benign) —
    that silently understates recall/AUC and a single NaN crashes roc_curve. The
    caller treats None as a per-entry error and excludes it."""
    try:
        s = float(pred.get("score"))
    except (TypeError, ValueError):
        return None
    if s != s or s in (float("inf"), float("-inf")):
        return None
    return s


PI_THREAT_TYPES = {"prompt_injection_direct", "prompt_injection_indirect"}
PHISHING_THREAT_TYPES = {"phishing", "scam", "spam"}

# Each task scopes which eval_roles count as positive / negative. Records whose
# role is in neither set are out of scope and excluded entirely — this is how
# phishing is kept out of the PI false-positive denominator under task=pi.
TASK_SCOPE = {
    "pi": ({"pi_positive"}, {"negative"}),
    "phishing": ({"phishing"}, {"negative"}),
    "any-malicious": ({"pi_positive", "phishing"}, {"negative"}),
}


def eval_role(entry: dict) -> str:
    """Evaluation role of a record: pi_positive | phishing | negative.

    Prefers the explicit eval_role tag written by combine_manifests.py; falls
    back to deriving it from threat_type so older manifests still grade.
    """
    role = entry.get("eval_role")
    if role:
        return role
    tt = entry["label"].get("threat_type", "")
    if tt in PI_THREAT_TYPES:
        return "pi_positive"
    if tt in PHISHING_THREAT_TYPES:
        return "phishing"
    return "negative"


def task_label(entry: dict, task: str) -> int | None:
    """1=positive, 0=negative, None=out of scope for this task."""
    pos, neg = TASK_SCOPE[task]
    role = eval_role(entry)
    if role in pos:
        return 1
    if role in neg:
        return 0
    return None


def compute_metrics(
    labels: list[int],
    scores: list[float],
    threshold: float = 0.35,
) -> dict:
    """Compute binary classification metrics at a fixed threshold."""
    preds = [1 if s >= threshold else 0 for s in scores]
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if len(set(labels)) < 2:
        # Only positives or only negatives — still show counts and recall/FPR.
        preds = [1 if s >= threshold else 0 for s in scores]
        if n_neg == 0:
            prec = 1.0 if sum(preds) > 0 else float("nan")
            rec = sum(preds) / n_pos if n_pos else float("nan")
            fpr = float("nan")
        else:
            fp = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 1)
            tn = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 0)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            prec = rec = float("nan")
        return {
            "n": len(labels),
            "n_pos": n_pos,
            "n_neg": n_neg,
            "threshold": threshold,
            "precision": round(float(prec), 4) if prec == prec else float("nan"),
            "recall": round(float(rec), 4) if rec == rec else float("nan"),
            "f1": float("nan"),
            "fpr": round(fpr, 4) if fpr == fpr else float("nan"),
            "auc_roc": float("nan"),
            "auc_pr": float("nan"),
            "tpr_at_1pct_fpr": float("nan"),
            "tpr_at_0.1pct_fpr": float("nan"),
            "note": "single-class bucket",
        }

    prec, rec, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )
    try:
        auc_roc = float(roc_auc_score(labels, scores))
    except Exception:
        auc_roc = float("nan")
    try:
        auc_pr = float(average_precision_score(labels, scores))
    except Exception:
        auc_pr = float("nan")

    # FPR at the chosen threshold
    tn = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 0)
    fp = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 1)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    n_pos = sum(labels)
    n_neg = len(labels) - n_pos

    tpr_fpr = tpr_at_fpr(labels, scores)

    return {
        "n": len(labels),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "threshold": threshold,
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(fpr, 4),
        "auc_roc": round(auc_roc, 4),
        "auc_pr": round(auc_pr, 4),
        "tpr_at_1pct_fpr": round(tpr_fpr[0.01], 4),
        "tpr_at_0.1pct_fpr": round(tpr_fpr[0.001], 4),
    }


def cross_fire(
    manifest: dict[str, dict],
    predictions: dict[str, dict],
    threshold: float,
) -> dict | None:
    """Over-trigger rate on phishing records.

    PI detectors are not meant to catch phishing; this measures how often they
    fire on it anyway. Reported separately, never folded into a task's FPR.
    """
    scores: list[float] = []
    flagged = 0
    for id_, entry in manifest.items():
        if eval_role(entry) != "phishing":
            continue
        pred = predictions.get(id_)
        if not pred or pred.get("error"):
            continue
        s = _score_or_none(pred)
        if s is None:
            continue
        scores.append(s)
        if s >= threshold:
            flagged += 1
    n = len(scores)
    if n == 0:
        return None
    return {
        "n_phishing": n,
        "flag_rate": round(flagged / n, 4),
        "mean_score": round(sum(scores) / n, 4),
        "threshold": threshold,
    }


def slice_by(
    manifest: dict[str, dict],
    predictions: dict[str, dict],
    key: str,
    threshold: float,
    task: str,
) -> dict[str, dict]:
    """Compute metrics for each value of a manifest field (task-scoped)."""
    buckets: dict[str, tuple[list[int], list[float]]] = defaultdict(lambda: ([], []))

    for id_, entry in manifest.items():
        label = task_label(entry, task)
        if label is None:
            continue
        if id_ not in predictions:
            continue
        pred = predictions[id_]
        if pred.get("error"):
            continue

        score = _score_or_none(pred)
        if score is None:
            continue

        if key == "surface":
            for surf in entry.get("surface", ["unknown"]):
                buckets[surf][0].append(label)
                buckets[surf][1].append(score)
        elif key == "threat_type":
            tt = entry["label"].get("threat_type", "unknown")
            buckets[tt][0].append(label)
            buckets[tt][1].append(score)
        elif key == "split":
            sp = entry.get("split", "unknown")
            buckets[sp][0].append(label)
            buckets[sp][1].append(score)
        else:
            val = str(entry.get(key, "unknown"))
            buckets[val][0].append(label)
            buckets[val][1].append(score)

    return {
        bucket: compute_metrics(labels, scores, threshold)
        for bucket, (labels, scores) in sorted(buckets.items())
    }


def grade_detector(
    name: str,
    manifest: dict[str, dict],
    pred_path: str,
    slice_keys: list[str],
    threshold: float,
    task: str,
) -> dict:
    predictions = load_predictions(pred_path)

    labels: list[int] = []
    scores: list[float] = []
    error_count = 0
    n_in_scope = 0

    for id_, entry in manifest.items():
        label = task_label(entry, task)
        if label is None:
            continue  # out of scope for this task (e.g. phishing under task=pi)
        n_in_scope += 1
        if id_ not in predictions:
            continue
        pred = predictions[id_]
        if pred.get("error"):
            error_count += 1
            continue
        s = _score_or_none(pred)
        if s is None:
            error_count += 1
            continue
        labels.append(label)
        scores.append(s)

    coverage = len(labels) / n_in_scope if n_in_scope else 0.0
    result: dict = {
        "detector": name,
        "task": task,
        "coverage": round(coverage, 4),
        "error_count": error_count,
        "overall": compute_metrics(labels, scores, threshold),
    }

    for sk in slice_keys:
        result[f"by_{sk}"] = slice_by(manifest, predictions, sk, threshold, task)

    # Cross-fire diagnostic: how often this detector fires on phishing (reported
    # for every task, never folded into the task's own positives/negatives).
    cf = cross_fire(manifest, predictions, threshold)
    if cf:
        result["cross_fire_phishing"] = cf

    # Average latency for non-error predictions
    latencies = [
        p["latency_ms"]
        for p in predictions.values()
        if not p.get("error") and p.get("latency_ms")
    ]
    if latencies:
        result["latency_p50_ms"] = int(np.percentile(latencies, 50))
        result["latency_p95_ms"] = int(np.percentile(latencies, 95))

    return result


def print_table(metrics: list[dict]) -> None:
    # Threshold-free reporting: rank by AUC, with TPR at fixed low FPR as the
    # operating point. No single global cutoff is applied (it would put each
    # detector at a different, incomparable point on its curve).
    cols = ["n_pos", "n_neg", "auc_roc", "auc_pr", "tpr@1%fpr", "tpr@.1%fpr", "coverage"]
    header = f"{'detector':<40}" + "".join(f"  {c:>10}" for c in cols)
    print(header)
    print("-" * len(header))
    for m in metrics:
        ov = m.get("overall", {})
        print(
            f"{m['detector']:<40}"
            f"  {ov.get('n_pos', 0):>10}"
            f"  {ov.get('n_neg', 0):>10}"
            f"  {ov.get('auc_roc', float('nan')):>10.4f}"
            f"  {ov.get('auc_pr', float('nan')):>10.4f}"
            f"  {ov.get('tpr_at_1pct_fpr', float('nan')):>10.4f}"
            f"  {ov.get('tpr_at_0.1pct_fpr', float('nan')):>10.4f}"
            f"  {m.get('coverage', float('nan')):>10.4f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute detection metrics from a run directory."
    )
    parser.add_argument(
        "--run-dir",
        default="eval/runs/latest",
        help="directory containing manifest_used.jsonl and *.jsonl prediction files",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="root (if run-dir is relative)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.35,
        help="decision threshold for binary metrics (default 0.35)",
    )
    parser.add_argument(
        "--task",
        choices=["pi", "phishing", "any-malicious"],
        default="pi",
        help="which detection task to score (default: pi). "
        "pi=prompt-injection (phishing excluded from negatives); "
        "phishing=phishing/scam; any-malicious=PI+phishing positive",
    )
    parser.add_argument(
        "--slice",
        action="append",
        choices=["surface", "threat_type", "split", "sender_auth_condition"],
        default=None,
        help="slice metrics by this manifest field (repeatable)",
    )
    args = parser.parse_args()
    slice_keys = args.slice or []

    base = os.path.abspath(args.base_dir)
    run_dir = os.path.join(base, args.run_dir) if not os.path.isabs(args.run_dir) else args.run_dir

    manifest_path = os.path.join(run_dir, "manifest_used.jsonl")
    if not os.path.exists(manifest_path):
        sys.exit(f"manifest not found: {manifest_path}")

    manifest = load_manifest(manifest_path)
    roles: dict[str, int] = defaultdict(int)
    for e in manifest.values():
        roles[eval_role(e)] += 1
    role_summary = ", ".join(f"{r}={n}" for r, n in sorted(roles.items()))
    print(f"Ground truth: {len(manifest)} entries from {manifest_path}")
    print(f"Task: {args.task}  |  eval_role: {role_summary}")

    pred_files = sorted(
        f for f in os.listdir(run_dir)
        if f.endswith(".jsonl") and f != "manifest_used.jsonl"
    )
    if not pred_files:
        sys.exit("no prediction files found in run-dir")

    all_metrics: list[dict] = []
    for fname in pred_files:
        det_name = fname[:-6]  # strip .jsonl
        pred_path = os.path.join(run_dir, fname)
        print(f"Grading: {det_name}")
        m = grade_detector(det_name, manifest, pred_path, slice_keys, args.threshold, args.task)
        all_metrics.append(m)

    print()
    print_table(all_metrics)

    # Cross-fire diagnostic: over-trigger rate on phishing (all detectors).
    cf_rows = [(m["detector"], m["cross_fire_phishing"]) for m in all_metrics
               if m.get("cross_fire_phishing")]
    if cf_rows:
        print(f"\nCross-fire — flag rate on phishing (threshold={args.threshold}):")
        print(f"  {'detector':<14}  {'flag_rate':>9}  {'mean_score':>10}  {'n_phish':>8}")
        print("  " + "-" * 46)
        for det, cf in cf_rows:
            print(f"  {det:<14}  {cf['flag_rate']:>9.4f}  {cf['mean_score']:>10.4f}  {cf['n_phishing']:>8}")

    for sk in slice_keys:
        for m in all_metrics:
            slice_data = m.get(f"by_{sk}")
            if not slice_data:
                continue
            print(f"\n{m['detector']} — by {sk} (task={args.task}, threshold-free):")
            cols = ["n", "n_pos", "auc_roc", "auc_pr", "tpr@1%fpr"]
            header = f"  {'slice':<24}" + "".join(f"  {c:>10}" for c in cols)
            print(header)
            print("  " + "-" * (len(header) - 2))
            for bucket, bm in slice_data.items():
                print(
                    f"  {bucket:<24}"
                    f"  {bm.get('n', 0):>10}"
                    f"  {bm.get('n_pos', 0):>10}"
                    f"  {bm.get('auc_roc', float('nan')):>10.4f}"
                    f"  {bm.get('auc_pr', float('nan')):>10.4f}"
                    f"  {bm.get('tpr_at_1pct_fpr', float('nan')):>10.4f}"
                )

    metrics_path = os.path.join(run_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(
            {"task": args.task, "threshold": args.threshold,
             "slices": slice_keys, "detectors": all_metrics},
            f,
            indent=2,
        )
    print(f"\nmetrics written → {metrics_path}")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(__file__))
    main()

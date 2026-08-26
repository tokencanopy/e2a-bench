#!/usr/bin/env python3
"""run_eval.py — run one or more detectors over a manifest and write predictions.

Each detector writes its predictions to <out-dir>/<detector_name>.jsonl.
Run grade.py on the same output directory to compute metrics.

Reliability features (important for long unattended GCP runs):
  * Incremental writes — every prediction is flushed to disk as it completes,
    so a crash at entry 4000 doesn't lose the first 3999.
  * Resume — re-running the same command skips ids already present with a
    non-error prediction; previously-errored ids are retried.
  * Retry-with-backoff — transient API/network errors are retried before the
    prediction is recorded as a failure.

Usage:
    python3 eval/run_eval.py --detectors piguard --detectors llm \\
        --manifest eval/combined_manifest.jsonl \\
        --base-dir . \\
        --out-dir eval/runs/$(date +%Y%m%d)

    # HuggingFace local classifiers use the hf:<model_id> form:
    python3 eval/run_eval.py \\
        --detectors hf:protectai/deberta-v3-base-prompt-injection-v2 \\
        --detectors hf:leolee99/InjecGuard \\
        --detectors hf:fmops/distilbert-prompt-injection

Canonical detector input (REQUIRED for a real run): build the piguard-eval binary,
dump the typed segments, and point PIGUARD_SEGMENTS at the dump so every text
detector screens exactly what piguard sees (incl. hidden HTML + attachment/PDF
text). Without it, detectors fall back to a body-only reparse and the attachment
surfaces silently degrade.
    cd e2a && go build -o ../piguard-eval-bin ./cmd/piguard-eval
    export PIGUARD_EVAL_BIN=$PWD/piguard-eval-bin
    "$PIGUARD_EVAL_BIN" --dump-segments --base-dir . \\
        < eval/combined_manifest.jsonl > eval/segments.jsonl
    export PIGUARD_SEGMENTS=$PWD/eval/segments.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from tqdm import tqdm

from detectors import (
    Prediction,
    PiguardDetector,
    GeminiDetector,
    ModelArmorDetector,
    ScamGuardDetector,
    LakeraDetector,
    HFClassifierDetector,
    GCGSuffixDetector,
    GCGPerplexityDetector,
    PhishingClassifierDetector,
)

DETECTOR_REGISTRY: dict[str, type] = {
    "piguard": PiguardDetector,
    "gemini": GeminiDetector,
    "gemini-phishing": GeminiDetector,
    "gemini-vision": GeminiDetector,
    "gemini-vision-phishing": GeminiDetector,
    "modelarmor": ModelArmorDetector,
    "scamguard": ScamGuardDetector,
    "lakera": LakeraDetector,
    "gcg_suffix": GCGSuffixDetector,
    "gcg_perplexity": GCGPerplexityDetector,
    "phishing-logreg": PhishingClassifierDetector,
    "phishing-xgboost": PhishingClassifierDetector,
    "phishing-sgd": PhishingClassifierDetector,
}

# Detectors that run as one true batch call rather than per-entry HTTP.
_BATCH_TYPES = (PiguardDetector, HFClassifierDetector, GCGPerplexityDetector)

# Chunk size for batch detectors — small enough to persist progress often.
_BATCH_CHUNK = 256


def load_manifest(path: str) -> list[dict]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _valid_detector(name: str) -> bool:
    return name in DETECTOR_REGISTRY or name.startswith("hf:")


def build_detector(name: str, base_dir: str, args: argparse.Namespace):
    # Detector input is sourced from the canonical piguard segment dump via
    # detectors/segment_input.py (PIGUARD_SEGMENTS); there is no Python-side
    # cleanup knob anymore (the old --eml-cleanup path was removed).
    if name.startswith("hf:"):
        return HFClassifierDetector(
            model_id=name[len("hf:"):],
            base_dir=base_dir,
            batch_size=args.hf_batch_size,
        )
    if name == "piguard":
        return PiguardDetector(
            binary=args.piguard_bin,
            base_dir=base_dir,
            review_threshold=args.review_threshold,
            block_threshold=args.block_threshold,
        )
    if name == "gemini":
        return GeminiDetector(model=args.gemini_model, base_dir=base_dir, task="injection")
    if name == "gemini-phishing":
        return GeminiDetector(model=args.gemini_model, base_dir=base_dir, task="phishing")
    if name == "gemini-vision":
        return GeminiDetector(model=args.gemini_model, base_dir=base_dir, task="injection", vision=True)
    if name == "gemini-vision-phishing":
        return GeminiDetector(model=args.gemini_model, base_dir=base_dir, task="phishing", vision=True)
    if name == "phishing-logreg":
        return PhishingClassifierDetector(
            model_type="logreg",
            artifact_path=args.phishing_logreg_artifact,
            base_dir=base_dir,
            threshold=args.phishing_threshold,
        )
    if name == "phishing-xgboost":
        return PhishingClassifierDetector(
            model_type="xgboost",
            artifact_path=args.phishing_xgboost_artifact,
            base_dir=base_dir,
            threshold=args.phishing_threshold,
        )
    if name == "phishing-sgd":
        return PhishingClassifierDetector(
            model_type="sgd",
            artifact_path=args.phishing_sgd_artifact,
            base_dir=base_dir,
            threshold=args.phishing_threshold,
        )
    if name == "modelarmor":
        return ModelArmorDetector(
            project=args.modelarmor_project,
            location=args.modelarmor_location,
            template=args.modelarmor_template,
            base_dir=base_dir,
        )
    if name == "scamguard":
        return ScamGuardDetector(base_dir=base_dir)
    if name == "lakera":
        return LakeraDetector(base_dir=base_dir)
    if name == "gcg_suffix":
        kwargs = {"base_dir": base_dir}
        if args.gcg_review_threshold is not None:
            kwargs["review_threshold"] = args.gcg_review_threshold
        if args.gcg_block_threshold is not None:
            kwargs["block_threshold"] = args.gcg_block_threshold
        return GCGSuffixDetector(**kwargs)
    if name == "gcg_perplexity":
        return GCGPerplexityDetector(
            base_dir=base_dir,
            model_id=args.gcg_perplexity_model,
            thresholds_path=args.gcg_perplexity_thresholds,
            batch_size=args.gcg_perplexity_batch_size,
        )
    raise ValueError(f"unknown detector: {name!r}")


def _load_done_ids(path: str) -> set[str]:
    """Ids already present with a non-error prediction (so resume re-runs failures)."""
    done: set[str] = set()
    if not os.path.exists(path):
        return done
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                pred = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not pred.get("error"):
                done.add(pred["id"])
    return done


def _compact(path: str) -> None:
    """Collapse the append log to one (last-wins) line per id, sorted by id."""
    if not os.path.exists(path):
        return
    by_id: dict[str, dict] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                pred = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_id[pred["id"]] = pred
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for _id in sorted(by_id):
            f.write(json.dumps(by_id[_id]) + "\n")
    os.replace(tmp, path)


def _predict_with_retry(
    detector, entry: dict, max_retries: int, base_delay: float
) -> Prediction:
    pred = detector.predict(entry)
    attempt = 0
    # Retry transient failures (network/API). Parse errors are permanent.
    while (
        pred.error
        and not pred.error.startswith("parse:")
        and attempt < max_retries
    ):
        time.sleep(base_delay * (2 ** attempt))
        attempt += 1
        pred = detector.predict(entry)
    return pred


def run_detector(
    detector,
    entries: list[dict],
    out_path: str,
    max_retries: int,
    base_delay: float,
    workers: int = 1,
) -> None:
    name = detector.name
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    done = _load_done_ids(out_path)
    remaining = [e for e in entries if e["id"] not in done]
    if done:
        print(f"  [{name}] resume: {len(done)} already done, {len(remaining)} remaining")
    if not remaining:
        print(f"  [{name}] already complete ({len(done)} predictions) → {out_path}")
        _compact(out_path)
        return

    errors = 0
    # Append mode so partial progress survives a crash; compacted at the end.
    with open(out_path, "a") as f:
        if isinstance(detector, _BATCH_TYPES):
            print(f"  [{name}] batching {len(remaining)} entries "
                  f"(chunks of {_BATCH_CHUNK})...")
            t0 = time.monotonic()
            for start in range(0, len(remaining), _BATCH_CHUNK):
                chunk = remaining[start:start + _BATCH_CHUNK]
                for p in detector.predict_batch(chunk):
                    f.write(p.to_jsonl_line() + "\n")
                    errors += 1 if p.error else 0
                f.flush()
                os.fsync(f.fileno())
            elapsed = time.monotonic() - t0
            rate = len(remaining) / elapsed if elapsed else 0.0
            print(f"  [{name}] done in {elapsed:.1f}s  ({rate:.0f} msg/s)")
        elif workers > 1:
            # I/O-bound API/subprocess detectors: fan out with a thread pool.
            # Results are written from THIS thread as futures complete, so the
            # file append needs no lock. Resume still works (keyed by id).
            from concurrent.futures import ThreadPoolExecutor, as_completed
            print(f"  [{name}] {len(remaining)} entries, {workers} workers...")
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_predict_with_retry, detector, e, max_retries, base_delay)
                        for e in remaining]
                for fut in tqdm(as_completed(futs), total=len(remaining),
                                desc=f"  [{name}]", unit="msg"):
                    p = fut.result()
                    f.write(p.to_jsonl_line() + "\n")
                    f.flush()
                    errors += 1 if p.error else 0
        else:
            for entry in tqdm(remaining, desc=f"  [{name}]", unit="msg"):
                p = _predict_with_retry(detector, entry, max_retries, base_delay)
                f.write(p.to_jsonl_line() + "\n")
                f.flush()
                errors += 1 if p.error else 0

    _compact(out_path)
    total = len(_load_done_ids(out_path)) + errors
    print(f"  [{name}] wrote predictions ({errors} errors this run) → {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run detectors over an eval manifest and write predictions JSONL."
    )
    parser.add_argument(
        "--manifest",
        default="eval/combined_manifest.jsonl",
        help="combined PI + ham manifest (from combine_manifests.py)",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="root directory (resolves manifest eml_path values)",
    )
    parser.add_argument(
        "--detectors",
        action="append",
        default=[],
        metavar="NAME",
        help=f"detector to run (repeatable); registry: {list(DETECTOR_REGISTRY)} "
             f"or hf:<model_id>",
    )
    parser.add_argument(
        "--out-dir",
        default="eval/runs/latest",
        help="directory for prediction JSONL outputs",
    )
    # reliability
    parser.add_argument("--max-retries", type=int, default=3,
                        help="retry count for transient API errors (default 3)")
    parser.add_argument("--retry-base-delay", type=float, default=1.0,
                        help="base seconds for exponential backoff (default 1.0)")
    parser.add_argument("--workers", type=int, default=1,
                        help="concurrent requests for API/subprocess detectors "
                             "(default 1=sequential; HF batched detectors stay sequential)")
    # piguard options
    parser.add_argument(
        "--piguard-bin",
        default=os.environ.get("PIGUARD_EVAL_BIN", "piguard-eval"),
        help="path to piguard-eval binary",
    )
    parser.add_argument("--review-threshold", type=float, default=0.35)
    parser.add_argument("--block-threshold", type=float, default=0.75)
    parser.add_argument(
        "--gcg-review-threshold",
        type=float,
        default=None,
        help="override gcg_suffix review threshold (default: detector default)",
    )
    parser.add_argument(
        "--gcg-block-threshold",
        type=float,
        default=None,
        help="override gcg_suffix block threshold (default: detector default)",
    )
    parser.add_argument(
        "--gcg-perplexity-model",
        default=os.environ.get("GCG_PERPLEXITY_MODEL", "distilbert/distilgpt2"),
        help="causal LM for gcg_perplexity (default: distilbert/distilgpt2)",
    )
    parser.add_argument(
        "--gcg-perplexity-batch-size",
        type=int,
        default=8,
        help="mini-batch size for gcg_perplexity (default 8)",
    )
    parser.add_argument(
        "--gcg-perplexity-thresholds",
        default=None,
        help="threshold JSON for gcg_perplexity (default: detector bundled file)",
    )
    # HF options
    parser.add_argument("--hf-batch-size", type=int, default=32,
                        help="mini-batch size for HF classifiers (default 32)")
    # LLM judge options
    parser.add_argument(
        "--gemini-model",
        default=os.environ.get("GEMINI_EVAL_MODEL", "gemini-2.5-flash"),
        help="Google model for the Gemini detector",
    )
    parser.add_argument(
        "--gemini-max-tokens",
        type=int,
        default=int(os.environ.get("GEMINI_EVAL_MAX_TOKENS", "2048")),
        help="max output tokens for Gemini JSON verdicts (default 2048)",
    )
    # local phishing classifier options
    parser.add_argument(
        "--phishing-logreg-artifact",
        default=os.environ.get("PHISHING_LOGREG_ARTIFACT"),
        help="joblib artifact for phishing-logreg",
    )
    parser.add_argument(
        "--phishing-xgboost-artifact",
        default=os.environ.get("PHISHING_XGBOOST_ARTIFACT"),
        help="joblib artifact for phishing-xgboost",
    )
    parser.add_argument(
        "--phishing-sgd-artifact",
        default=os.environ.get("PHISHING_SGD_ARTIFACT"),
        help="joblib artifact for phishing-sgd",
    )
    parser.add_argument(
        "--phishing-threshold",
        type=float,
        default=None,
        help="override local phishing classifier decision threshold",
    )
    # Model Armor options
    parser.add_argument(
        "--modelarmor-project",
        default=os.environ.get("MODELARMOR_PROJECT", ""),
        help="GCP project ID for Model Armor",
    )
    parser.add_argument(
        "--modelarmor-location",
        default=os.environ.get("MODELARMOR_LOCATION", "us-central1"),
        help="GCP region for Model Armor (default: us-central1)",
    )
    parser.add_argument(
        "--modelarmor-template",
        default=os.environ.get("MODELARMOR_TEMPLATE", "pi-eval"),
        help="Model Armor template ID (default: pi-eval)",
    )
    args = parser.parse_args()

    if not args.detectors:
        parser.error("specify at least one --detectors name")
    for d in args.detectors:
        if not _valid_detector(d):
            parser.error(
                f"unknown detector {d!r}; choices: {list(DETECTOR_REGISTRY)} "
                f"or hf:<model_id>"
            )

    base_dir = os.path.abspath(args.base_dir)
    manifest_path = os.path.join(base_dir, args.manifest) if not os.path.isabs(args.manifest) else args.manifest
    if not os.path.exists(manifest_path):
        sys.exit(f"manifest not found: {manifest_path}\n"
                 "Run: python3 eval/combine_manifests.py")

    entries = load_manifest(manifest_path)
    n_pos = sum(1 for e in entries if e["label"]["is_malicious"])
    n_neg = len(entries) - n_pos
    print(f"Loaded {len(entries)} entries ({n_pos} positive, {n_neg} negative)")

    out_dir = os.path.join(base_dir, args.out_dir) if not os.path.isabs(args.out_dir) else args.out_dir
    os.makedirs(out_dir, exist_ok=True)

    # Save a copy of the manifest subset used, for reproducibility.
    with open(os.path.join(out_dir, "manifest_used.jsonl"), "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    for det_name in args.detectors:
        print(f"\nRunning detector: {det_name}")
        try:
            detector = build_detector(det_name, base_dir, args)
        except (ValueError, ImportError) as exc:
            print(f"  skip: {exc}", file=sys.stderr)
            continue

        # Output file is named by the detector's own (model-qualified) name so
        # hf:* and multi-model runs don't collide.
        out_path = os.path.join(out_dir, f"{detector.name}.jsonl")
        run_detector(detector, entries, out_path,
                     args.max_retries, args.retry_base_delay, args.workers)

    print(f"\nDone. Run grade.py --run-dir {out_dir}")


if __name__ == "__main__":
    # Make detectors importable when run from repo root.
    sys.path.insert(0, os.path.dirname(__file__))
    main()

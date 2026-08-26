#!/usr/bin/env python3
"""Train a TF-IDF phishing classifier from EmailRecord manifests.

The classifier consumes subject + flattened body segments from
`detectors.segment_input.parts_for`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import types
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PHISHING_THREAT_TYPES = {"phishing", "scam"}
DEFAULT_NEGATIVE_THREAT_TYPES = {"benign"}


def _ensure_detectors_stub() -> None:
    """Register a minimal 'detectors' package stub in sys.modules so that
    `from detectors.segment_input import parts_for` loads segment_input.py
    without executing __init__.py (which requires API packages such as anthropic
    that are not needed for offline training).  Has no effect when the real
    package has already been imported."""
    if "detectors" not in sys.modules:
        stub = types.ModuleType("detectors")
        stub.__path__ = [str(Path(__file__).resolve().parent / "detectors")]
        stub.__package__ = "detectors"
        sys.modules["detectors"] = stub


_ensure_detectors_stub()


def load_manifest(path: str) -> list[dict]:
    entries: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def parse_threat_types(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def label_for(entry: dict, positive_types: set[str],
              negative_types: set[str]) -> int | None:
    threat_type = entry.get("label", {}).get("threat_type")
    if threat_type in positive_types:
        return 1
    if threat_type in negative_types:
        return 0
    return None


def training_rows(entries: list[dict], base_dir: str,
                  max_body_chars: int,
                  positive_types: set[str] | None = None,
                  negative_types: set[str] | None = None) -> tuple[list[dict], list[str], list[int]]:
    from detectors.segment_input import parts_for

    positive_types = positive_types or PHISHING_THREAT_TYPES
    negative_types = negative_types or DEFAULT_NEGATIVE_THREAT_TYPES
    kept: list[dict] = []
    texts: list[str] = []
    labels: list[int] = []
    for entry in entries:
        label = label_for(entry, positive_types, negative_types)
        if label is None:
            continue
        subject, _from, body = parts_for(entry, base_dir, max_body_chars=max_body_chars)
        kept.append(entry)
        texts.append(f"Subject: {subject}\n\n{body}")
        labels.append(label)
    return kept, texts, labels


def group_key(entry: dict) -> str:
    """Group likely template siblings so train/eval do not share subject families."""
    subject = entry.get("detector_input", {}).get("subject", "") or ""
    subject = re.sub(r"\d+", "#", subject.lower())
    subject = re.sub(r"\s+", " ", subject)
    subject = re.sub(r"[^a-z0-9# ]+", "", subject).strip()
    if subject:
        return f"subject:{subject[:160]}"
    return f"id:{entry['id']}"


def write_jsonl(path: str, entries: list[dict], split_name: str) -> None:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    with open(path, "w") as f:
        for entry in entries:
            out = dict(entry)
            out["split"] = split_name
            f.write(json.dumps(out) + "\n")


def build_classifier(model_type: str, args: argparse.Namespace):
    if model_type == "logreg":
        from sklearn.linear_model import LogisticRegression
        return LogisticRegression(
            C=args.logreg_c,
            max_iter=args.logreg_max_iter,
            class_weight="balanced",
            solver="liblinear",
            random_state=args.seed,
        )
    if model_type == "sgd":
        from sklearn.linear_model import SGDClassifier
        return SGDClassifier(
            loss="log_loss",
            penalty="elasticnet",
            alpha=args.sgd_alpha,
            l1_ratio=args.sgd_l1_ratio,
            max_iter=args.sgd_max_iter,
            tol=args.sgd_tol,
            class_weight="balanced",
            random_state=args.seed,
            n_jobs=args.sgd_n_jobs,
        )
    if model_type == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise ImportError(
                "Install xgboost for --model xgboost: pip install xgboost"
            ) from exc
        return XGBClassifier(
            n_estimators=args.xgb_estimators,
            max_depth=args.xgb_max_depth,
            learning_rate=args.xgb_learning_rate,
            subsample=args.xgb_subsample,
            colsample_bytree=args.xgb_colsample_bytree,
            eval_metric="logloss",
            min_child_weight=args.xgb_min_child_weight,
            gamma=args.xgb_gamma,
            reg_alpha=args.xgb_reg_alpha,
            reg_lambda=args.xgb_reg_lambda,
            n_jobs=args.xgb_n_jobs,
            random_state=args.seed,
        )
    raise ValueError(f"unsupported model: {model_type}")


def maybe_calibrate(classifier, enabled: bool, cv: int):
    if not enabled:
        return classifier
    from sklearn.calibration import CalibratedClassifierCV

    return CalibratedClassifierCV(classifier, method="sigmoid", cv=cv)


def build_vectorizer(args: argparse.Namespace):
    from sklearn.feature_extraction.text import TfidfVectorizer
    if args.vectorizer == "hashing-word-char":
        from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
        from sklearn.pipeline import FeatureUnion, Pipeline
        return FeatureUnion([
            ("word", Pipeline([
                ("hash", HashingVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    analyzer="word",
                    ngram_range=(args.ngram_min, args.ngram_max),
                    n_features=args.hashing_features,
                    alternate_sign=False,
                    norm=None,
                )),
                ("tfidf", TfidfTransformer(sublinear_tf=True)),
            ])),
            ("char", Pipeline([
                ("hash", HashingVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    analyzer="char_wb",
                    ngram_range=(args.char_ngram_min, args.char_ngram_max),
                    n_features=args.char_hashing_features,
                    alternate_sign=False,
                    norm=None,
                )),
                ("tfidf", TfidfTransformer(sublinear_tf=True)),
            ])),
        ])

    if args.vectorizer == "word":
        return TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(args.ngram_min, args.ngram_max),
            max_features=args.max_features,
            min_df=args.min_df,
            sublinear_tf=True,
        )

    from sklearn.pipeline import FeatureUnion
    return FeatureUnion([
        ("word", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            analyzer="word",
            ngram_range=(args.ngram_min, args.ngram_max),
            max_features=args.max_features,
            min_df=args.min_df,
            sublinear_tf=True,
        )),
        ("char", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            analyzer="char_wb",
            ngram_range=(args.char_ngram_min, args.char_ngram_max),
            max_features=args.char_max_features,
            min_df=args.char_min_df,
            sublinear_tf=True,
        )),
    ])


def split_indices(
    kept: list[dict],
    labels: list[int],
    eval_size: float,
    seed: int,
    split_strategy: str,
) -> tuple[list[int], list[int]]:
    from sklearn.model_selection import GroupShuffleSplit, train_test_split

    idx = list(range(len(kept)))
    if split_strategy == "random":
        train_idx, eval_idx = train_test_split(
            idx, test_size=eval_size, random_state=seed, stratify=labels,
        )
        return list(train_idx), list(eval_idx)

    groups = [group_key(e) for e in kept]
    for offset in range(25):
        splitter = GroupShuffleSplit(
            n_splits=1, test_size=eval_size, random_state=seed + offset,
        )
        train_idx, eval_idx = next(splitter.split(idx, labels, groups))
        train_idx = list(train_idx)
        eval_idx = list(eval_idx)
        train_labels = [labels[i] for i in train_idx]
        eval_labels = [labels[i] for i in eval_idx]
        if len(set(train_labels)) == 2 and len(set(eval_labels)) == 2:
            return train_idx, eval_idx
    raise SystemExit("grouped split failed to keep both classes in train/eval")


def train_tune_split(train_idx: list[int], labels: list[int], tune_size: float,
                     seed: int) -> tuple[list[int], list[int]]:
    from sklearn.model_selection import train_test_split

    train_labels = [labels[i] for i in train_idx]
    counts = Counter(train_labels)
    if min(counts.values()) < 2:
        raise SystemExit(
            "training split is too small for threshold tuning; use more data, "
            "a smaller --eval-size, or --threshold-policy fixed"
        )
    if tune_size <= 0:
        return list(train_idx), list(train_idx)
    fit_idx, tune_idx = train_test_split(
        train_idx, test_size=tune_size, random_state=seed, stratify=train_labels,
    )
    return list(fit_idx), list(tune_idx)


def choose_threshold(labels: list[int], scores, policy: str, target_fpr: float,
                     fixed_threshold: float) -> tuple[float, dict]:
    from sklearn.metrics import precision_recall_fscore_support

    if policy == "fixed":
        return fixed_threshold, {"policy": "fixed", "threshold": fixed_threshold}

    candidates = sorted({0.0, 1.0, fixed_threshold, *[float(s) for s in scores]})
    best: tuple[float, float, float, float] | None = None
    for threshold in candidates:
        preds = [1 if float(s) >= threshold else 0 for s in scores]
        tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
        fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
        tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
        fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        if policy == "target-fpr" and fpr > target_fpr:
            continue
        objective = recall if policy == "target-fpr" else f1
        candidate = (objective, -fpr, precision, threshold)
        if best is None or candidate > best:
            best = candidate

    if best is None:
        threshold = 1.0
    else:
        threshold = best[3]

    preds = [1 if float(s) >= threshold else 0 for s in scores]
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0,
    )
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return float(threshold), {
        "policy": policy,
        "threshold": float(threshold),
        "target_fpr": target_fpr if policy == "target-fpr" else None,
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
    }


def score_summary(classifier, vectorizer, texts: list[str], labels: list[int],
                  threshold: float) -> dict:
    from sklearn.metrics import (
        average_precision_score,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    if not texts:
        return {}
    features = vectorizer.transform(texts)
    scores = classifier.predict_proba(features)[:, 1]
    preds = [1 if s >= threshold else 0 for s in scores]
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0,
    )
    out = {
        "n": len(labels),
        "n_pos": int(sum(labels)),
        "n_neg": int(len(labels) - sum(labels)),
        "threshold": threshold,
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
    }
    if len(set(labels)) >= 2:
        out["auc_roc"] = round(float(roc_auc_score(labels, scores)), 4)
        out["auc_pr"] = round(float(average_precision_score(labels, scores)), 4)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train TF-IDF + LogisticRegression/XGBoost phishing detector."
    )
    parser.add_argument("--manifest", default="dataset/phishing/manifest.jsonl")
    parser.add_argument(
        "--external-eval-manifest",
        default=None,
        help="optional held-out manifest; when set, --manifest is used only for training",
    )
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--model", choices=["logreg", "xgboost", "sgd"], default="logreg")
    parser.add_argument("--artifact-out", default=None)
    parser.add_argument("--train-manifest-out", default="eval/phishing_train_manifest.jsonl")
    parser.add_argument("--eval-manifest-out", default="eval/phishing_eval_manifest.jsonl")
    parser.add_argument("--eval-size", type=float, default=0.2)
    parser.add_argument("--split-strategy", choices=["grouped", "random"], default="grouped")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold", type=float, default=0.35)
    parser.add_argument("--threshold-policy", choices=["target-fpr", "f1", "fixed"], default="fixed")
    parser.add_argument("--target-fpr", type=float, default=0.01)
    parser.add_argument("--tune-size", type=float, default=0.2)
    parser.add_argument("--max-body-chars", type=int, default=20000)
    parser.add_argument(
        "--positive-threat-types",
        default="phishing,scam",
        help="comma-separated threat_type values treated as positive labels",
    )
    parser.add_argument(
        "--negative-threat-types",
        default="benign",
        help="comma-separated threat_type values treated as negative labels; add spam for hard-negative training",
    )
    parser.add_argument(
        "--vectorizer",
        choices=["word-char", "word", "hashing-word-char"],
        default="word-char",
    )
    parser.add_argument("--max-features", type=int, default=30000)
    parser.add_argument("--min-df", type=int, default=3)
    parser.add_argument("--ngram-min", type=int, default=1)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--char-max-features", type=int, default=30000)
    parser.add_argument("--char-min-df", type=int, default=3)
    parser.add_argument("--char-ngram-min", type=int, default=3)
    parser.add_argument("--char-ngram-max", type=int, default=6)
    parser.add_argument("--hashing-features", type=int, default=2**20)
    parser.add_argument("--char-hashing-features", type=int, default=2**20)
    parser.add_argument("--calibrate", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--calibration-cv", type=int, default=3)
    parser.add_argument("--logreg-c", type=float, default=1.0)
    parser.add_argument("--logreg-max-iter", type=int, default=1000)
    parser.add_argument("--xgb-estimators", type=int, default=200)
    parser.add_argument("--xgb-max-depth", type=int, default=3)
    parser.add_argument("--xgb-learning-rate", type=float, default=0.05)
    parser.add_argument("--xgb-subsample", type=float, default=0.8)
    parser.add_argument("--xgb-colsample-bytree", type=float, default=0.8)
    parser.add_argument("--xgb-min-child-weight", type=float, default=3.0)
    parser.add_argument("--xgb-gamma", type=float, default=0.1)
    parser.add_argument("--xgb-reg-alpha", type=float, default=0.5)
    parser.add_argument("--xgb-reg-lambda", type=float, default=2.0)
    parser.add_argument("--xgb-n-jobs", type=int, default=4)
    parser.add_argument("--sgd-alpha", type=float, default=1e-5)
    parser.add_argument("--sgd-l1-ratio", type=float, default=0.05)
    parser.add_argument("--sgd-max-iter", type=int, default=20)
    parser.add_argument("--sgd-tol", type=float, default=1e-4)
    parser.add_argument("--sgd-n-jobs", type=int, default=-1)
    args = parser.parse_args()

    try:
        import joblib
    except ImportError as exc:
        raise SystemExit(
            "Install training dependencies: pip install -r eval/requirements.txt"
        ) from exc

    base_dir = os.path.abspath(args.base_dir)
    positive_types = parse_threat_types(args.positive_threat_types)
    negative_types = parse_threat_types(args.negative_threat_types)
    manifest_path = (
        args.manifest if os.path.isabs(args.manifest)
        else os.path.join(base_dir, args.manifest)
    )
    entries = load_manifest(manifest_path)
    kept, texts, labels = training_rows(
        entries, base_dir, args.max_body_chars, positive_types, negative_types,
    )
    counts = Counter(labels)
    if counts[0] == 0 or counts[1] == 0:
        raise SystemExit(f"need both classes after filtering; got {dict(counts)}")

    external_eval = args.external_eval_manifest is not None
    if external_eval:
        eval_manifest_path = (
            args.external_eval_manifest if os.path.isabs(args.external_eval_manifest)
            else os.path.join(base_dir, args.external_eval_manifest)
        )
        eval_kept, eval_texts, eval_labels = training_rows(
            load_manifest(eval_manifest_path), base_dir, args.max_body_chars,
            positive_types, negative_types,
        )
        eval_counts = Counter(eval_labels)
        if eval_counts[0] == 0 or eval_counts[1] == 0:
            raise SystemExit(
                f"external eval needs both classes after filtering; got {dict(eval_counts)}"
            )
        train_idx = list(range(len(kept)))
        eval_idx: list[int] = []
    else:
        train_idx, eval_idx = split_indices(
            kept, labels, args.eval_size, args.seed, args.split_strategy,
        )
        eval_kept = [kept[i] for i in eval_idx]
        eval_texts = [texts[i] for i in eval_idx]
        eval_labels = [labels[i] for i in eval_idx]

    fit_idx, tune_idx = train_tune_split(train_idx, labels, args.tune_size, args.seed)

    fit_texts = [texts[i] for i in fit_idx]
    fit_labels = [labels[i] for i in fit_idx]
    tune_texts = [texts[i] for i in tune_idx]
    tune_labels = [labels[i] for i in tune_idx]
    final_train_texts = [texts[i] for i in train_idx]
    final_train_labels = [labels[i] for i in train_idx]

    tune_vectorizer = build_vectorizer(args)
    tune_features = tune_vectorizer.fit_transform(fit_texts)
    tune_classifier = maybe_calibrate(
        build_classifier(args.model, args), args.calibrate, args.calibration_cv,
    )
    tune_classifier.fit(tune_features, fit_labels)
    tune_scores = tune_classifier.predict_proba(tune_vectorizer.transform(tune_texts))[:, 1]
    selected_threshold, threshold_report = choose_threshold(
        tune_labels, tune_scores, args.threshold_policy, args.target_fpr, args.threshold,
    )

    vectorizer = build_vectorizer(args)
    train_features = vectorizer.fit_transform(final_train_texts)
    classifier = maybe_calibrate(
        build_classifier(args.model, args), args.calibrate, args.calibration_cv,
    )
    classifier.fit(train_features, final_train_labels)

    artifact_out = args.artifact_out or f"eval/artifacts/phishing_tfidf_{args.model}.joblib"
    artifact_path = (
        artifact_out if os.path.isabs(artifact_out)
        else os.path.join(base_dir, artifact_out)
    )
    artifact_dir = os.path.dirname(artifact_path)
    if artifact_dir:
        os.makedirs(artifact_dir, exist_ok=True)
    artifact = {
        "model_type": args.model,
        "vectorizer": vectorizer,
        "classifier": classifier,
        "threshold": selected_threshold,
        "metadata": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "manifest": args.manifest,
            "n_total": len(kept),
            "n_train": len(train_idx),
            "n_fit": len(fit_idx),
            "n_tune": len(tune_idx),
            "n_eval": len(eval_kept),
            "label_counts": dict(counts),
            "positive_threat_types": sorted(positive_types),
            "negative_threat_types": sorted(negative_types),
            "seed": args.seed,
            "eval_size": args.eval_size,
            "split_strategy": "external" if external_eval else args.split_strategy,
            "external_eval_manifest": args.external_eval_manifest,
            "text_view": "subject + canonical body segments",
            "vectorizer": args.vectorizer,
            "calibrated": args.calibrate,
            "threshold_selection": threshold_report,
        },
    }
    joblib.dump(artifact, artifact_path)

    train_manifest = (
        args.train_manifest_out if os.path.isabs(args.train_manifest_out)
        else os.path.join(base_dir, args.train_manifest_out)
    )
    eval_manifest = (
        args.eval_manifest_out if os.path.isabs(args.eval_manifest_out)
        else os.path.join(base_dir, args.eval_manifest_out)
    )
    write_jsonl(train_manifest, [kept[i] for i in train_idx], "train")
    write_jsonl(eval_manifest, eval_kept, "test")

    summary = {
        "artifact": artifact_path,
        "train_manifest": train_manifest,
        "eval_manifest": eval_manifest,
        "threshold_selection": threshold_report,
        "train": score_summary(classifier, vectorizer, final_train_texts, final_train_labels, selected_threshold),
        "eval": score_summary(classifier, vectorizer, eval_texts, eval_labels, selected_threshold),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()

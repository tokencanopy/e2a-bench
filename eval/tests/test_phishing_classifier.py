from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

EVAL_DIR = Path(__file__).resolve().parents[1]
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))


def _write_eml(path: Path, subject: str, body: str, sender: str = "a@example.com") -> None:
    path.write_text(
        f"From: {sender}\n"
        "To: user@example.com\n"
        f"Subject: {subject}\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}\n",
        encoding="utf-8",
    )


def _write_tiny_manifest(tmp_path: Path) -> Path:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    rows = []
    for i in range(8):
        rows.append((
            f"phish{i}",
            f"Verify your account {i}",
            f"Urgent password reset at http://fake-login{i}.test",
            "phishing",
            True,
        ))
        rows.append((
            f"ham{i}",
            f"Project update {i}",
            f"The team lunch and project status notes are confirmed for item {i}",
            "benign",
            False,
        ))
    manifest = tmp_path / "manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as f:
        for id_, subject, body, threat_type, malicious in rows:
            eml = dataset / f"{id_}.eml"
            _write_eml(eml, subject, body)
            rec = {
                "id": id_,
                "eml_path": str(eml.relative_to(tmp_path)),
                "label": {"is_malicious": malicious, "threat_type": threat_type},
                "provenance": {"source": "synthetic", "synthetic": True},
            }
            f.write(json.dumps(rec) + "\n")
    return manifest


def _import_run_eval_with_api_mocks():
    """Import run_eval while mocking API packages unavailable in offline dev environments."""
    import types

    def _stub(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        m.__spec__ = None  # prevent importlib from re-resolving
        return m

    api_stubs = {
        "anthropic": _stub("anthropic"),
        "requests": _stub("requests"),
        "google": _stub("google"),
        "google.genai": _stub("google.genai"),
        "google.auth": _stub("google.auth"),
        "google.auth.credentials": _stub("google.auth.credentials"),
        "google.generativeai": _stub("google.generativeai"),
    }
    # clear any previously imported detectors / run_eval so the mock takes effect
    to_delete = [k for k in sys.modules if k in ("run_eval",) or k.startswith("detectors")]
    for k in to_delete:
        del sys.modules[k]
    with patch.dict(sys.modules, api_stubs):
        import run_eval as _run_eval
    return _run_eval


def test_run_eval_registry_contains_phishing_detectors():
    run_eval = _import_run_eval_with_api_mocks()
    assert "phishing-logreg" in run_eval.DETECTOR_REGISTRY
    assert "phishing-xgboost" in run_eval.DETECTOR_REGISTRY
    assert "phishing-sgd" in run_eval.DETECTOR_REGISTRY


def test_run_eval_builds_phishing_logreg_with_artifact_arg():
    import types

    def _stub(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        m.__spec__ = None
        return m

    api_stubs = {
        "anthropic": _stub("anthropic"),
        "requests": _stub("requests"),
        "google": _stub("google"),
        "google.genai": _stub("google.genai"),
        "google.auth": _stub("google.auth"),
        "google.auth.credentials": _stub("google.auth.credentials"),
    }
    to_delete = [k for k in sys.modules if k in ("run_eval",) or k.startswith("detectors")]
    for k in to_delete:
        del sys.modules[k]

    with patch.dict(sys.modules, api_stubs):
        import run_eval

        args = argparse.Namespace(
            phishing_logreg_artifact="/tmp/logreg.joblib",
            phishing_xgboost_artifact="/tmp/xgb.joblib",
            phishing_sgd_artifact="/tmp/sgd.joblib",
            phishing_threshold=0.42,
        )
        with patch.object(run_eval, "PhishingClassifierDetector") as mock_detector:
            run_eval.build_detector("phishing-logreg", ".", args)

    _, kwargs = mock_detector.call_args
    assert kwargs["model_type"] == "logreg"
    assert kwargs["artifact_path"] == "/tmp/logreg.joblib"
    assert kwargs["threshold"] == 0.42


def test_run_eval_builds_phishing_sgd_with_artifact_arg():
    import types

    def _stub(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        m.__spec__ = None
        return m

    api_stubs = {
        "anthropic": _stub("anthropic"),
        "requests": _stub("requests"),
        "google": _stub("google"),
        "google.genai": _stub("google.genai"),
        "google.auth": _stub("google.auth"),
        "google.auth.credentials": _stub("google.auth.credentials"),
    }
    to_delete = [k for k in sys.modules if k in ("run_eval",) or k.startswith("detectors")]
    for k in to_delete:
        del sys.modules[k]

    with patch.dict(sys.modules, api_stubs):
        import run_eval

        args = argparse.Namespace(
            phishing_logreg_artifact="/tmp/logreg.joblib",
            phishing_xgboost_artifact="/tmp/xgb.joblib",
            phishing_sgd_artifact="/tmp/sgd.joblib",
            phishing_threshold=0.44,
        )
        with patch.object(run_eval, "PhishingClassifierDetector") as mock_detector:
            run_eval.build_detector("phishing-sgd", ".", args)

    _, kwargs = mock_detector.call_args
    assert kwargs["model_type"] == "sgd"
    assert kwargs["artifact_path"] == "/tmp/sgd.joblib"
    assert kwargs["threshold"] == 0.44


def test_ensemble_uses_max_score_and_survives_single_error(tmp_path: Path):
    from ensemble_predictions import combine_one

    local = {"id": "m1", "score": 0.41, "latency_ms": 3}
    gemini = {"id": "m1", "score": 0.83, "latency_ms": 7}
    rec = combine_one("m1", local, gemini, 0.35, "ensemble")
    assert rec["score"] == 0.83
    assert rec["flagged"] is True
    assert rec["action"] == "block"
    assert rec["latency_ms"] == 10

    rec = combine_one("m2", {"id": "m2", "error": "boom"}, {"id": "m2", "score": 0.2}, 0.35, "ensemble")
    assert rec["score"] == 0.2
    assert rec.get("error") is None

    rec = combine_one("m3", {"id": "m3", "error": "boom"}, None, 0.35, "ensemble")
    assert rec["error"] == "local=boom; gemini=missing"


def test_ensemble_gemini_primary_ignores_local_when_gemini_available():
    from ensemble_predictions import combine_one

    rec = combine_one(
        "m1",
        {"id": "m1", "score": 0.99},
        {"id": "m1", "score": 0.2},
        0.35,
        "ensemble",
        "gemini_primary",
    )
    assert rec["score"] == 0.2
    assert rec["flagged"] is False
    assert rec["categories"][0]["strategy"] == "gemini_primary"


def test_train_logreg_artifact_and_detector_predict(tmp_path: Path, monkeypatch):
    pytest.importorskip("sklearn")
    pytest.importorskip("joblib")

    import train_phishing_classifier
    from detectors.phishing_classifier import PhishingClassifierDetector

    manifest = _write_tiny_manifest(tmp_path)
    artifact = tmp_path / "artifact.joblib"
    train_out = tmp_path / "train.jsonl"
    eval_out = tmp_path / "eval.jsonl"
    monkeypatch.setattr(sys, "argv", [
        "train_phishing_classifier.py",
        "--base-dir", str(tmp_path),
        "--manifest", str(manifest),
        "--model", "logreg",
        "--artifact-out", str(artifact),
        "--train-manifest-out", str(train_out),
        "--eval-manifest-out", str(eval_out),
        "--eval-size", "0.5",
        "--min-df", "1",
        "--threshold", "0.35",
        "--threshold-policy", "fixed",
        "--no-calibrate",
    ])
    train_phishing_classifier.main()

    assert artifact.exists()
    assert train_out.exists()
    assert eval_out.exists()

    det = PhishingClassifierDetector(
        model_type="logreg",
        artifact_path=str(artifact),
        base_dir=str(tmp_path),
    )
    entry = {
        "id": "new-phish",
        "eml_path": "dataset/new-phish.eml",
    }
    _write_eml(
        tmp_path / entry["eml_path"],
        "Password reset required",
        "Verify credentials immediately at http://fake-login.test",
    )
    pred = det.predict(entry)
    assert pred.detector == "phishing_tfidf_logreg"
    assert 0.0 <= pred.score <= 1.0
    assert pred.error is None


def test_build_xgboost_classifier_when_dependency_is_available():
    xgboost = pytest.importorskip("xgboost")
    import train_phishing_classifier

    args = argparse.Namespace(
        xgb_estimators=2,
        xgb_max_depth=1,
        xgb_learning_rate=0.1,
        xgb_subsample=1.0,
        xgb_colsample_bytree=1.0,
        xgb_min_child_weight=1.0,
        xgb_gamma=0.0,
        xgb_reg_alpha=0.0,
        xgb_reg_lambda=1.0,
        xgb_n_jobs=1,
        seed=42,
    )
    clf = train_phishing_classifier.build_classifier("xgboost", args)
    assert clf.__class__.__name__ == xgboost.XGBClassifier.__name__


def test_build_sgd_classifier_and_hashing_vectorizer():
    pytest.importorskip("sklearn")
    import train_phishing_classifier

    args = argparse.Namespace(
        sgd_alpha=1e-5,
        sgd_l1_ratio=0.05,
        sgd_max_iter=2,
        sgd_tol=1e-4,
        sgd_n_jobs=1,
        seed=42,
        vectorizer="hashing-word-char",
        ngram_min=1,
        ngram_max=2,
        char_ngram_min=3,
        char_ngram_max=5,
        hashing_features=2**10,
        char_hashing_features=2**10,
    )
    clf = train_phishing_classifier.build_classifier("sgd", args)
    vectorizer = train_phishing_classifier.build_vectorizer(args)
    features = vectorizer.fit_transform(["Subject: reset\n\nclick link", "Subject: lunch\n\nteam notes"])

    assert clf.__class__.__name__ == "SGDClassifier"
    assert features.shape == (2, 2**11)

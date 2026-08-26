"""PhishingClassifierDetector — TF-IDF phishing email classifier adapter.

Loads an offline-trained artifact produced by `eval/train_phishing_classifier.py`
and scores subject + canonical body text. This is intentionally a local, cheap
phishing/lure detector to pair with API judges such as Gemini.

Environment:
    PHISHING_LOGREG_ARTIFACT   artifact for `phishing-logreg`
    PHISHING_XGBOOST_ARTIFACT  artifact for `phishing-xgboost`
    PHISHING_SGD_ARTIFACT      artifact for `phishing-sgd`
    PHISHING_CLASSIFIER_ARTIFACT generic fallback artifact path
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .base import Prediction

_SUPPORTED_MODELS = ("logreg", "xgboost", "sgd")


def _action_from_score(score: float, review_threshold: float = 0.35,
                       block_threshold: float = 0.75) -> str:
    if score >= block_threshold:
        return "block"
    if score >= review_threshold:
        return "review"
    return "allow"


def _default_artifact(model_type: str, base_dir: str) -> str:
    env_key = {
        "logreg": "PHISHING_LOGREG_ARTIFACT",
        "xgboost": "PHISHING_XGBOOST_ARTIFACT",
        "sgd": "PHISHING_SGD_ARTIFACT",
    }[model_type]
    configured = (
        os.environ.get(env_key)
        or os.environ.get("PHISHING_CLASSIFIER_ARTIFACT")
        or f"eval/artifacts/phishing_tfidf_{model_type}.joblib"
    )
    if os.path.isabs(configured):
        return configured
    return str(Path(base_dir) / configured)


class PhishingClassifierDetector:
    def __init__(
        self,
        model_type: str = "logreg",
        artifact_path: str | None = None,
        base_dir: str = ".",
        threshold: float | None = None,
        max_body_chars: int = 20000,
    ) -> None:
        if model_type not in _SUPPORTED_MODELS:
            raise ValueError(
                f"model_type must be one of {_SUPPORTED_MODELS}, got {model_type!r}"
            )
        self._model_type = model_type
        self._base_dir = base_dir
        self._artifact_path = artifact_path or _default_artifact(model_type, base_dir)
        self._max_body_chars = max_body_chars

        try:
            import joblib
        except ImportError as exc:
            raise ImportError("Install joblib + scikit-learn: pip install joblib scikit-learn") from exc

        artifact = joblib.load(self._artifact_path)
        self._vectorizer = artifact["vectorizer"]
        self._classifier = artifact["classifier"]
        self._threshold = float(
            threshold if threshold is not None else artifact.get("threshold", 0.35)
        )
        self._metadata = artifact.get("metadata", {})
        artifact_type = artifact.get("model_type")
        if artifact_type and artifact_type != model_type:
            raise ValueError(
                f"artifact model_type {artifact_type!r} does not match detector {model_type!r}"
            )

    @property
    def name(self) -> str:
        return f"phishing_tfidf_{self._model_type}"

    def predict(self, entry: dict) -> Prediction:
        det = self.name
        try:
            from .segment_input import parts_for
            subject, _from, body = parts_for(
                entry, self._base_dir, max_body_chars=self._max_body_chars
            )
        except Exception as exc:
            return Prediction(
                id=entry["id"], detector=det, flagged=False, score=0.0,
                error=f"parse: {exc}",
            )

        text = _format_email_text(subject, body)
        start = time.monotonic()
        try:
            features = self._vectorizer.transform([text])
            score = _positive_probability(self._classifier, features)
        except Exception as exc:
            return Prediction(
                id=entry["id"], detector=det, flagged=False, score=0.0,
                error=f"classifier: {exc}",
            )
        latency_ms = int((time.monotonic() - start) * 1000)

        score = max(0.0, min(1.0, float(score)))
        flagged = score >= self._threshold
        return Prediction(
            id=entry["id"],
            detector=det,
            flagged=flagged,
            score=score,
            action=_action_from_score(score),
            categories=[{
                "name": "phishing",
                "model_type": self._model_type,
                "artifact": self._artifact_path,
                "threshold": self._threshold,
            }],
            latency_ms=latency_ms,
        )


def _format_email_text(subject: str, body: str) -> str:
    return f"Subject: {subject}\n\n{body}"


def _positive_probability(classifier, features) -> float:
    if hasattr(classifier, "predict_proba"):
        probs = classifier.predict_proba(features)
        return float(probs[0, 1]) if probs.shape[1] >= 2 else float(probs[0, 0])
    if hasattr(classifier, "decision_function"):
        import math
        margin = float(classifier.decision_function(features)[0])
        return 1.0 / (1.0 + math.exp(-margin))
    return float(classifier.predict(features)[0])

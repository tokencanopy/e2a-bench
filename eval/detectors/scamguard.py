"""ScamGuardDetector — Scam-Guard / checkreality.ai API adapter.

Sends the canonical segment view to the Scam-Guard inbound-scan API
(POST /v1/inbound/scan) and normalizes the response into the shared Prediction
format. Schema per scam-guard-api-reference.pdf v0.1.0 (2026-06-16).

Input note: we send the canonical piguard segment blob (same input the OSS
baselines and LLM judges see) as `raw_email` with content_type=text/plain, so
the row stays directly comparable to the rest of the benchmark. This does
bypass Scam-Guard's own hidden-content extraction; to instead exercise its
native extraction, send the raw .eml with content_type=text/html.

Environment:
    SCAMGUARD_API_KEY   required
    SCAMGUARD_API_URL   override endpoint (default: https://api.checkreality.ai/v1/inbound/scan)
"""
from __future__ import annotations

import os
import time

import requests

from .base import Prediction

_DEFAULT_URL = os.environ.get(
    "SCAMGUARD_API_URL", "https://api.checkreality.ai/v1/inbound/scan"
)
_API_KEY = os.environ.get("SCAMGUARD_API_KEY", "")


class ScamGuardDetector:
    def __init__(
        self,
        api_key: str = _API_KEY,
        api_url: str = _DEFAULT_URL,
        base_dir: str = ".",
        timeout: int = 15,
    ) -> None:
        if not api_key:
            raise ValueError("SCAMGUARD_API_KEY is not set")
        self._api_key = api_key
        self._api_url = api_url
        self._base_dir = base_dir
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {self._api_key}"})

    @property
    def name(self) -> str:
        return "scamguard"

    def predict(self, entry: dict) -> Prediction:
        try:
            from .segment_input import content_for
            body = content_for(entry, self._base_dir, max_chars=8000)
        except Exception as exc:
            return Prediction(id=entry["id"], detector="scamguard",
                              flagged=False, score=0.0, error=f"parse: {exc}")

        start = time.monotonic()
        try:
            resp = self._session.post(
                self._api_url,
                json={"raw_email": body, "content_type": "text/plain"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            return Prediction(id=entry["id"], detector="scamguard",
                              flagged=False, score=0.0, error=str(exc)[:200])

        latency_ms = int((time.monotonic() - start) * 1000)

        # Normalize Scam-Guard /v1/inbound/scan response (schema v0.1.0):
        #   {"verdict": allow|flag|block, "score": 0..1, "signals": [{code,..}], ...}
        # `score` is the continuous injection-risk value the benchmark grades on.
        verdict = str(data.get("verdict", "allow")).lower()
        score = max(0.0, min(1.0, float(data.get("score", 0.0))))
        flagged = verdict in ("flag", "block")

        # Scam-Guard's own documented bands: flag >= 0.40, block >= 0.75.
        action = "allow"
        if score >= 0.75:
            action = "block"
        elif score >= 0.40:
            action = "review"

        categories = [
            {"name": str(sig.get("code"))}
            for sig in data.get("signals", []) or []
            if isinstance(sig, dict) and sig.get("code")
        ]

        return Prediction(
            id=entry["id"],
            detector="scamguard",
            flagged=flagged,
            score=score,
            action=action,
            categories=categories,
            latency_ms=latency_ms,
        )

"""LakeraDetector — Lakera Guard API adapter.

Sends the canonical segment view to Lakera Guard's screening endpoint
(POST /v2/guard/results) and normalizes the response into the shared Prediction
format.

We read Lakera's dedicated prompt-injection detector, `prompt_attack`, whose
verdict is a 5-level ordinal confidence band (L1 = confident attack ... L5 =
unlikely). Like Google Model Armor's 3-level categorical confidence, this is a
*coarse* score: it collapses to five discrete values, so Lakera's AUC-ROC /
TPR@low-FPR are coarser than the continuous-score detectors. We map the band to
a graded score in [0,1]:  l1->1.0, l2->0.75, l3->0.5, l4->0.25, l5->0.0.

Input note: we send the flattened canonical piguard segment blob (same input the
OSS baselines and other commercial APIs see) as a single user message, so the row
stays directly comparable to the rest of the benchmark.

Environment:
    LAKERA_API_KEY   required
    LAKERA_API_URL   override endpoint (default: https://api.lakera.ai/v2/guard/results)
"""
from __future__ import annotations

import os
import re
import time

import requests

from .base import Prediction

_DEFAULT_URL = os.environ.get(
    "LAKERA_API_URL", "https://api.lakera.ai/v2/guard/results"
)
_API_KEY = os.environ.get("LAKERA_API_KEY", "")

# Lakera's prompt-injection detector and its ordinal confidence scale.
_PI_DETECTOR = "prompt_attack"
_LEVEL_RE = re.compile(r"l([1-5])")
# level n in 1..5 -> graded score (l1 = confident attack = 1.0, l5 = unlikely = 0.0)
_LEVEL_SCORE = {1: 1.0, 2: 0.75, 3: 0.5, 4: 0.25, 5: 0.0}


class LakeraDetector:
    def __init__(
        self,
        api_key: str = _API_KEY,
        api_url: str = _DEFAULT_URL,
        base_dir: str = ".",
        timeout: int = 15,
    ) -> None:
        if not api_key:
            raise ValueError("LAKERA_API_KEY is not set")
        self._api_key = api_key
        self._api_url = api_url
        self._base_dir = base_dir
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {self._api_key}"})

    @property
    def name(self) -> str:
        return "lakera"

    def predict(self, entry: dict) -> Prediction:
        try:
            from .segment_input import content_for
            text = content_for(entry, self._base_dir, max_chars=8000)
        except Exception as exc:
            return Prediction(id=entry["id"], detector="lakera",
                              flagged=False, score=0.0, error=f"parse: {exc}")

        payload = {"messages": [{"role": "user", "content": text}]}
        start = time.monotonic()
        try:
            resp = self._session.post(
                self._api_url,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            return Prediction(id=entry["id"], detector="lakera",
                              flagged=False, score=0.0, error=str(exc)[:200])

        latency_ms = int((time.monotonic() - start) * 1000)

        # Response: {"results": [{"detector_type": "prompt_attack", "result": "l1_confident", ...}, ...]}
        results = data.get("results", []) or []
        pi = next(
            (r for r in results
             if isinstance(r, dict) and r.get("detector_type") == _PI_DETECTOR),
            None,
        )
        if pi is None:
            # The prompt-injection detector isn't in the policy response — record
            # a per-entry error rather than silently scoring 0 (a confident benign).
            return Prediction(id=entry["id"], detector="lakera",
                              flagged=False, score=0.0,
                              error=f"parse: no {_PI_DETECTOR} detector in response")

        m = _LEVEL_RE.match(str(pi.get("result", "")))
        if not m:
            return Prediction(id=entry["id"], detector="lakera",
                              flagged=False, score=0.0,
                              error=f"parse: unrecognized level {pi.get('result')!r}")
        level = int(m.group(1))
        score = _LEVEL_SCORE[level]

        # Lakera's default policy blocks the confident bands (L1/L2).
        flagged = level <= 2
        action = "allow"
        if score >= 0.75:
            action = "block"
        elif score >= 0.40:
            action = "review"

        return Prediction(
            id=entry["id"],
            detector="lakera",
            flagged=flagged,
            score=score,
            action=action,
            categories=[{"name": _PI_DETECTOR, "score": score}],
            latency_ms=latency_ms,
        )

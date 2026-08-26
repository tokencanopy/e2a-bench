"""ModelArmorDetector — Google Cloud Model Armor adapter.

Model Armor is Google Cloud's dedicated prompt-injection and jailbreak detection
service. It requires a GCP project with the Model Armor API enabled and a
pre-created detection template.

Verified working config (e2a-protocol, 2026-07): the template must exist in the
SAME location the detector calls. The e2a benchmark uses the `us` multi-region
template `e2a`, so MODELARMOR_LOCATION must be `us` (NOT the us-central1 default).
Auth is Application Default Credentials — a user cred is fine; usage bills to the
project. NOTE: the gcloud CLI may be blocked by a VPC-SC perimeter even when the
ADC data-plane call (sanitizeUserPrompt) succeeds, so verify via the API, not the CLI.

Setup:
    1. Enable Model Armor API:
           gcloud services enable modelarmor.googleapis.com --project=YOUR_PROJECT
    2. Create a template with the PI/jailbreak filter enabled (Cloud Console or CLI):
           gcloud model-armor templates create e2a --location=us --project=YOUR_PROJECT \
               --pi-and-jailbreak-filter-settings-enforcement=enabled \
               --pi-and-jailbreak-filter-settings-confidence-level=LOW_AND_ABOVE
    3. Set the environment variables below (see repo .env)
    4. Authenticate: gcloud auth application-default login

Environment:
    MODELARMOR_PROJECT    GCP project ID (required)
    MODELARMOR_LOCATION   template location; must match the template (default: us-central1)
    MODELARMOR_TEMPLATE   template ID (default: pi-eval)
"""
from __future__ import annotations

import os
import time

import requests

from .base import Prediction

_PROJECT = os.environ.get("MODELARMOR_PROJECT", "")
_LOCATION = os.environ.get("MODELARMOR_LOCATION", "us-central1")
_TEMPLATE = os.environ.get("MODELARMOR_TEMPLATE", "pi-eval")

# Model Armor REST endpoint
_BASE_URL = "https://modelarmor.{location}.rep.googleapis.com/v1"

# Model Armor's PI/jailbreak filter emits only a categorical DetectionConfidenceLevel
# (no numeric 0-1 score), so we map it to a graded value to give the threshold-free
# metrics (AUC, TPR@1%FPR) some resolution. Covers both the bare and "_AND_ABOVE"
# spellings the API may return. NOTE: this yields at most 4 distinct score levels, so
# Model Armor's AUC/TPR@1%FPR are inherently coarse vs the continuous-score detectors.
_CONF_SCORE = {
    "HIGH": 1.0,
    "MEDIUM_AND_ABOVE": 0.75, "MEDIUM": 0.75,
    "LOW_AND_ABOVE": 0.5, "LOW": 0.5,
}
_MATCH_NO_CONF = 0.6  # matched but confidenceLevel absent/unspecified


def _endpoint(project: str, location: str, template: str) -> str:
    base = _BASE_URL.format(location=location)
    return (
        f"{base}/projects/{project}/locations/{location}"
        f"/templates/{template}:sanitizeUserPrompt"
    )


def _get_access_token() -> str:
    """Fetch a short-lived token via Application Default Credentials."""
    import google.auth
    import google.auth.transport.requests

    creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


class ModelArmorDetector:
    def __init__(
        self,
        project: str = _PROJECT,
        location: str = _LOCATION,
        template: str = _TEMPLATE,
        base_dir: str = ".",
        timeout: int = 15,
    ) -> None:
        if not project:
            raise ValueError(
                "MODELARMOR_PROJECT is not set. "
                "Set it to your GCP project ID."
            )
        self._project = project
        self._location = location
        self._template = template
        self._base_dir = base_dir
        self._timeout = timeout
        self._endpoint = _endpoint(project, location, template)
        self._session = requests.Session()
        self._token: str | None = None
        self._token_expiry: float = 0.0

    @property
    def name(self) -> str:
        return "modelarmor"

    def _auth_header(self) -> str:
        # Refresh token if expired (tokens are valid ~1h; refresh every 55 min)
        if self._token is None or time.monotonic() > self._token_expiry:
            try:
                self._token = _get_access_token()
            except Exception as exc:
                raise RuntimeError(
                    f"Model Armor auth failed: {exc}\n"
                    "Run: gcloud auth application-default login"
                ) from exc
            self._token_expiry = time.monotonic() + 3300  # 55 min
        return f"Bearer {self._token}"

    def predict(self, entry: dict) -> Prediction:
        try:
            from .segment_input import content_for
            text = content_for(entry, self._base_dir, max_chars=8000)
        except Exception as exc:
            return Prediction(id=entry["id"], detector="modelarmor",
                              flagged=False, score=0.0, error=f"parse: {exc}")

        payload = {"userPromptData": {"text": text}}
        try:
            auth = self._auth_header()
        except RuntimeError as exc:
            return Prediction(id=entry["id"], detector="modelarmor",
                              flagged=False, score=0.0, error=str(exc)[:200])

        start = time.monotonic()
        try:
            resp = self._session.post(
                self._endpoint,
                json=payload,
                headers={"Authorization": auth, "Content-Type": "application/json"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            return Prediction(id=entry["id"], detector="modelarmor",
                              flagged=False, score=0.0, error=str(exc)[:200])

        latency_ms = int((time.monotonic() - start) * 1000)

        # Response (verified against live API, filter v1):
        #   sanitizationResult.filterResults["pi_and_jailbreak"]
        #       .piAndJailbreakFilterResult = {matchState, confidenceLevel?}
        # We key on the PI/jailbreak filter specifically (not the top-level
        # filterMatchState, which also fires on csam/rai/malicious_uris).
        result = data.get("sanitizationResult", {})
        pj = (
            result.get("filterResults", {})
            .get("pi_and_jailbreak", {})
            .get("piAndJailbreakFilterResult", {})
        )
        flagged = pj.get("matchState") == "MATCH_FOUND"
        if flagged:
            score = _CONF_SCORE.get(pj.get("confidenceLevel"), _MATCH_NO_CONF)
        else:
            score = 0.0

        action = "block" if score >= 0.75 else ("review" if score >= 0.35 else "allow")

        return Prediction(
            id=entry["id"],
            detector="modelarmor",
            flagged=flagged,
            score=score,
            action=action,
            latency_ms=latency_ms,
        )

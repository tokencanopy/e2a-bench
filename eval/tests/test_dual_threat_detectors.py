"""Offline tests for the dual-threat (injection + phishing) GeminiDetector.

All Gemini client calls are monkeypatched — no API keys required.
(The Anthropic/Claude LLM detector was removed from the eval — too expensive.)
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CANNED_INJECTION = json.dumps({
    "injection": True,
    "injection_confidence": 0.92,
    "phishing": False,
    "phishing_confidence": 0.05,
    "rationale": "Email instructs the agent to forward all messages.",
})

_CANNED_PHISHING = json.dumps({
    "injection": False,
    "injection_confidence": 0.03,
    "phishing": True,
    "phishing_confidence": 0.88,
    "rationale": "Fake PayPal security notice with credential-harvesting link.",
})

_ENTRY = {"id": "test-001", "eml_path": "fake.eml"}


def _fake_extract(*args, **kwargs):
    return "Test Subject", "sender@example.com", "Hello world"


# ---------------------------------------------------------------------------
# GeminiDetector tests
# ---------------------------------------------------------------------------

class TestGeminiDetector:
    def _make_detector(self, task: str, canned_json: str):
        from detectors.gemini import GeminiDetector

        det = GeminiDetector.__new__(GeminiDetector)
        det._model = "gemini-2.5-flash"
        det._base_dir = "."
        det._max_tokens = 2048
        det._task = task
        det._vision = False
        det._thinking_off = True
        det._client = MagicMock()

        # Patch _call_api directly so we skip google-genai internals
        det._call_api = MagicMock(return_value=canned_json)

        return det

    def test_name_injection(self):
        from detectors.gemini import GeminiDetector
        with patch("google.genai.Client"):
            det = GeminiDetector(api_key="fake", task="injection")
        assert det.name == "gemini_gemini_2_5_flash_injection"

    def test_name_phishing(self):
        from detectors.gemini import GeminiDetector
        with patch("google.genai.Client"):
            det = GeminiDetector(api_key="fake", task="phishing")
        assert det.name == "gemini_gemini_2_5_flash_phishing"

    def test_invalid_task(self):
        from detectors.gemini import GeminiDetector
        with patch("google.genai.Client"):
            with pytest.raises(ValueError, match="task must be"):
                GeminiDetector(api_key="fake", task="malware")

    def test_injection_task_score(self):
        det = self._make_detector("injection", _CANNED_INJECTION)
        with patch("detectors.segment_input.parts_for", side_effect=_fake_extract):
            pred = det.predict(_ENTRY)
        assert pred.flagged is True
        assert abs(pred.score - 0.92) < 1e-6
        assert pred.detector == "gemini_gemini_2_5_flash_injection"

    def test_phishing_task_score(self):
        det = self._make_detector("phishing", _CANNED_PHISHING)
        with patch("detectors.segment_input.parts_for", side_effect=_fake_extract):
            pred = det.predict(_ENTRY)
        assert pred.flagged is True
        assert abs(pred.score - 0.88) < 1e-6
        assert pred.detector == "gemini_gemini_2_5_flash_phishing"

    def test_both_confidences_in_categories(self):
        det = self._make_detector("injection", _CANNED_PHISHING)
        with patch("detectors.segment_input.parts_for", side_effect=_fake_extract):
            pred = det.predict(_ENTRY)
        cats = pred.categories[0]
        assert abs(cats["injection_confidence"] - 0.03) < 1e-6
        assert abs(cats["phishing_confidence"] - 0.88) < 1e-6

    def test_bad_json_error(self):
        det = self._make_detector("phishing", "<<<bad>>>")
        with patch("detectors.segment_input.parts_for", side_effect=_fake_extract):
            pred = det.predict(_ENTRY)
        assert pred.error is not None
        assert "bad json" in pred.error


# ---------------------------------------------------------------------------
# run_eval registry / build_detector wiring
# ---------------------------------------------------------------------------

class TestRegistryWiring:
    def _make_args(self, **overrides):
        import argparse
        args = argparse.Namespace(
            eml_cleanup=False,
            gemini_model="gemini-2.5-flash",
            piguard_bin="piguard-eval",
            review_threshold=0.35,
            block_threshold=0.75,
            hf_batch_size=32,
            modelarmor_project="",
            modelarmor_location="us-central1",
            modelarmor_template="pi-eval",
        )
        for k, v in overrides.items():
            setattr(args, k, v)
        return args

    def test_registry_contains_gemini_keys(self):
        import importlib
        run_eval = importlib.import_module("run_eval")
        assert "gemini" in run_eval.DETECTOR_REGISTRY
        assert "gemini-phishing" in run_eval.DETECTOR_REGISTRY
        # the Anthropic/Claude detector was removed
        assert "llm" not in run_eval.DETECTOR_REGISTRY
        assert "llm-phishing" not in run_eval.DETECTOR_REGISTRY

    def test_build_gemini_injection(self):
        import importlib
        run_eval = importlib.import_module("run_eval")
        with patch("run_eval.GeminiDetector") as MockGemini:
            MockGemini.return_value._task = "injection"
            MockGemini.return_value.name = "gemini_gemini_2_5_flash_injection"
            run_eval.build_detector("gemini", ".", self._make_args())
        _, kwargs = MockGemini.call_args
        assert kwargs.get("task") == "injection"

    def test_build_gemini_phishing(self):
        import importlib
        run_eval = importlib.import_module("run_eval")
        with patch("run_eval.GeminiDetector") as MockGemini:
            MockGemini.return_value._task = "phishing"
            MockGemini.return_value.name = "gemini_gemini_2_5_flash_phishing"
            run_eval.build_detector("gemini-phishing", ".", self._make_args())
        _, kwargs = MockGemini.call_args
        assert kwargs.get("task") == "phishing"

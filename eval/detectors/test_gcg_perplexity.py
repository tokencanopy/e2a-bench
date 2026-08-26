from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.gcg_perplexity import GCGPerplexityDetector
from detectors.gcg_suffix import Segment

_REPO_ROOT = str(Path(__file__).resolve().parents[2])


def _make_detector() -> GCGPerplexityDetector:
    """Create a minimal GCGPerplexityDetector without loading any model.

    Uses __new__ to skip __init__ so tests can run without transformers/torch.
    Only the attributes accessed by the tested methods are populated.
    """
    det = GCGPerplexityDetector.__new__(GCGPerplexityDetector)
    det._tail_windows = (24, 32, 48, 64)
    det._prefix_window = 64
    det._score_center = 4.637915253029929
    det._score_scale = 1.6172081500417355
    det._review_threshold = 0.35
    det._block_threshold = 0.75
    det._max_segment_chars = 2400
    det._max_segments_per_message = 4
    det._batch_size = 8
    det._base_dir = _REPO_ROOT
    return det


class ScoreNLLTest(unittest.TestCase):
    """Unit tests for _score_nlls and _score_from_raw — no model required."""

    def setUp(self) -> None:
        self.det = _make_detector()
        # 96-token sequence: 64 "normal" tokens then 32 "chaotic" tokens.
        self._normal = [2.0] * 64
        self._chaotic = [11.0] * 32
        self._long_text = Segment("text", "x" * 500, indirect=False)

    def test_high_suffix_nll_scores_above_review(self) -> None:
        nlls = self._normal + self._chaotic
        ev = self.det._score_nlls(nlls, self._long_text)
        self.assertGreater(ev.score, 0.5,
                           "Suffix with NLL ≈ 11 vs prefix NLL ≈ 2 should score > 0.5")

    def test_uniform_nll_scores_below_review(self) -> None:
        nlls = [3.0] * 96
        ev = self.det._score_nlls(nlls, self._long_text)
        self.assertLess(ev.score, 0.35,
                        "Uniform NLL sequence has no tail anomaly; should be below review threshold")

    def test_too_short_returns_zero_score(self) -> None:
        nlls = [5.0] * 20  # fewer than 32 tokens; minimum for scoring
        ev = self.det._score_nlls(nlls, self._long_text)
        self.assertEqual(ev.score, 0.0)
        self.assertEqual(ev.window_tokens, 0)

    def test_url_in_tail_dampens_score(self) -> None:
        nlls = self._normal + self._chaotic
        seg_url = Segment("text", "x" * 450 + " https://example.com/redirect", indirect=False)
        ev_url = self.det._score_nlls(nlls, seg_url)
        ev_clean = self.det._score_nlls(nlls, self._long_text)
        self.assertLess(ev_url.score, ev_clean.score,
                        "URL in tail text should trigger ×0.58 dampener and lower score")

    def test_bulk_mail_in_tail_dampens_score(self) -> None:
        nlls = self._normal + self._chaotic
        seg_bulk = Segment("text", "x" * 450 + " unsubscribe from future offers", indirect=False)
        ev_bulk = self.det._score_nlls(nlls, seg_bulk)
        ev_clean = self.det._score_nlls(nlls, self._long_text)
        self.assertLess(ev_bulk.score, ev_clean.score,
                        "Bulk-mail keyword should trigger ×0.55 dampener and lower score")

    def test_score_from_raw_large_positive_approaches_one(self) -> None:
        self.assertGreater(self.det._score_from_raw(100.0), 0.99)

    def test_score_from_raw_large_negative_approaches_zero(self) -> None:
        self.assertLess(self.det._score_from_raw(-100.0), 0.01)

    def test_score_from_raw_at_center_is_half(self) -> None:
        mid = self.det._score_from_raw(self.det._score_center)
        self.assertAlmostEqual(mid, 0.5, delta=0.01)

    def test_best_window_is_reported(self) -> None:
        nlls = self._normal + self._chaotic
        ev = self.det._score_nlls(nlls, self._long_text)
        # The best scoring window should be one of the configured windows.
        self.assertIn(ev.window_tokens, self.det._tail_windows)

    def test_indirect_flag_propagates(self) -> None:
        nlls = self._normal + self._chaotic
        seg = Segment("text", "x" * 500, indirect=True)
        ev = self.det._score_nlls(nlls, seg)
        # indirect flag is taken from the segment when score > 0
        if ev.score > 0:
            self.assertTrue(ev.indirect)


class ThresholdLoadingTest(unittest.TestCase):
    """Unit tests for _load_thresholds — no model required."""

    def setUp(self) -> None:
        self.det = _make_detector()
        self.det._model_id = "distilbert/distilgpt2"

    def test_missing_file_keeps_defaults(self) -> None:
        self.det._load_thresholds("/nonexistent/path/thresholds.json")
        self.assertAlmostEqual(self.det._review_threshold, 0.35)
        self.assertAlmostEqual(self.det._block_threshold, 0.75)

    def test_empty_string_path_skips_loading(self) -> None:
        # Empty string is the sentinel used in calibrate_gcg_perplexity.py to
        # disable threshold loading entirely.
        self.det._review_threshold = 0.42
        self.det._load_thresholds("")
        self.assertAlmostEqual(self.det._review_threshold, 0.42,
                               msg="Empty-string path should be a no-op")

    def test_model_id_mismatch_skips_loading(self) -> None:
        data = {
            "model_id": "some-other-model",
            "review_threshold": 0.10,
            "block_threshold": 0.20,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp = f.name
        try:
            self.det._load_thresholds(tmp)
            self.assertAlmostEqual(self.det._review_threshold, 0.35,
                                   msg="Mismatched model_id should leave thresholds unchanged")
        finally:
            os.unlink(tmp)

    def test_valid_file_updates_all_fields(self) -> None:
        data = {
            "model_id": "distilbert/distilgpt2",
            "review_threshold": 0.28,
            "block_threshold": 0.60,
            "score_center": 3.5,
            "score_scale": 1.2,
            "tail_windows": [32, 48],
            "prefix_window": 48,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp = f.name
        try:
            self.det._load_thresholds(tmp)
            self.assertAlmostEqual(self.det._review_threshold, 0.28)
            self.assertAlmostEqual(self.det._block_threshold, 0.60)
            self.assertAlmostEqual(self.det._score_center, 3.5)
            self.assertAlmostEqual(self.det._score_scale, 1.2)
            self.assertEqual(self.det._tail_windows, (32, 48))
            self.assertEqual(self.det._prefix_window, 48)
        finally:
            os.unlink(tmp)

    def test_file_without_model_id_applies_unconditionally(self) -> None:
        data = {"review_threshold": 0.22, "block_threshold": 0.55}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp = f.name
        try:
            self.det._load_thresholds(tmp)
            self.assertAlmostEqual(self.det._review_threshold, 0.22)
        finally:
            os.unlink(tmp)


class ErrorPathTest(unittest.TestCase):
    """Unit tests for predict/predict_batch error handling — no model required."""

    def setUp(self) -> None:
        self.det = _make_detector()

    def test_missing_eml_predict_returns_error_prediction(self) -> None:
        pred = self.det.predict({"id": "bad", "eml_path": "no/such/file.eml"})
        self.assertFalse(pred.flagged)
        self.assertIsNotNone(pred.error)
        self.assertTrue(pred.error.startswith("parse:"))
        self.assertEqual(pred.score, 0.0)
        self.assertEqual(pred.action, "allow")

    def test_missing_eml_predict_batch_returns_error_prediction(self) -> None:
        preds = self.det.predict_batch([{"id": "bad", "eml_path": "no/such/file.eml"}])
        self.assertEqual(len(preds), 1)
        self.assertFalse(preds[0].flagged)
        self.assertIsNotNone(preds[0].error)

    def test_predict_and_predict_batch_agree_on_error(self) -> None:
        entry = {"id": "x", "eml_path": "no/such/file.eml"}
        single = self.det.predict(entry)
        batch = self.det.predict_batch([entry])
        self.assertEqual(single.flagged, batch[0].flagged)
        self.assertEqual(single.score, batch[0].score)
        self.assertEqual(single.action, batch[0].action)

    def test_multiple_error_entries_all_returned(self) -> None:
        entries = [
            {"id": f"bad_{i}", "eml_path": f"no/such/file_{i}.eml"}
            for i in range(4)
        ]
        preds = self.det.predict_batch(entries)
        self.assertEqual(len(preds), 4)
        for i, pred in enumerate(preds):
            self.assertEqual(pred.id, f"bad_{i}")
            self.assertIsNotNone(pred.error)

    def test_error_prediction_schema(self) -> None:
        pred = self.det.predict({"id": "err_schema", "eml_path": "no/such.eml"})
        self.assertEqual(pred.id, "err_schema")
        self.assertEqual(pred.detector, "gcg_perplexity")
        self.assertIsInstance(pred.latency_ms, int)
        self.assertGreaterEqual(pred.latency_ms, 0)


@unittest.skipUnless(
    os.environ.get("RUN_GCG_PERPLEXITY_TESTS") == "1",
    "set RUN_GCG_PERPLEXITY_TESTS=1 to run model-backed tests",
)
class GCGPerplexityIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = GCGPerplexityDetector(base_dir=_REPO_ROOT, batch_size=4)

    def test_real_jailbreakbench_gcg_majority_flagged(self) -> None:
        manifest = Path(_REPO_ROOT) / "dataset/prompt-injection/gcg-supplement/real/manifest.jsonl"
        entries = [
            json.loads(line)
            for line in manifest.read_text().splitlines()
            if line.strip()
        ]
        preds = self.detector.predict_batch(entries)
        valid = [p for p in preds if not p.error]
        flagged = [p for p in valid if p.flagged]
        self.assertGreater(
            len(valid), 0,
            "All JailbreakBench EML files failed to parse",
        )
        recall = len(flagged) / len(valid)
        self.assertGreaterEqual(
            recall, 0.5,
            f"Expected ≥50% recall on 8 JailbreakBench GCG samples, got {recall:.0%} "
            f"({len(flagged)}/{len(valid)})",
        )

    def test_benign_gcg_hard_negatives_not_flagged(self) -> None:
        stems = [
            "gcg_benign_0001_plaintext",
            "gcg_benign_0002_plaintext",
            "gcg_benign_0006_plaintext",
            "gcg_benign_0007_plaintext",
            "gcg_benign_0008_plaintext",
        ]
        entries = [
            {
                "id": stem,
                "eml_path": f"dataset/prompt-injection/gcg-supplement/eml/{stem}.eml",
            }
            for stem in stems
        ]
        for pred in self.detector.predict_batch(entries):
            with self.subTest(id=pred.id):
                self.assertIsNone(pred.error)
                self.assertFalse(pred.flagged,
                                 f"{pred.id} was falsely flagged (score={pred.score:.3f})")

    def test_prediction_schema_complete(self) -> None:
        entries = [
            json.loads(line)
            for line in (
                Path(_REPO_ROOT) / "dataset/prompt-injection/gcg-supplement/real/manifest.jsonl"
            ).read_text().splitlines()
            if line.strip()
        ][:2]
        for pred in self.detector.predict_batch(entries):
            self.assertEqual(pred.detector, "gcg_perplexity")
            self.assertIsInstance(pred.score, float)
            self.assertIn(pred.action, {"allow", "review", "block"})
            self.assertIsInstance(pred.latency_ms, int)
            if not pred.error:
                names = [c["name"] for c in pred.categories]
                self.assertIn("perplexity_tail_anomaly", names)


if __name__ == "__main__":
    unittest.main()

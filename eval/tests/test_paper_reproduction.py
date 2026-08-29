"""Regression tests for the frozen paper population and reproduction paths."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "eval" / "paper_manifest.jsonl"


def _rows() -> list[dict]:
    return [json.loads(line) for line in MANIFEST.read_text().splitlines() if line]


def test_frozen_manifest_hash_and_population() -> None:
    expected_hash = (ROOT / "eval" / "paper_manifest.sha256").read_text().split()[0]
    assert hashlib.sha256(MANIFEST.read_bytes()).hexdigest() == expected_hash

    rows = _rows()
    assert len(rows) == 6333
    assert Counter(row["eval_role"] for row in rows) == {
        "pi_positive": 2794,
        "phishing": 1500,
        "negative": 2039,
    }


def test_spam_is_a_phishing_family_positive() -> None:
    spam = [row for row in _rows() if row["label"]["threat_type"] == "spam"]
    assert len(spam) == 500
    assert {row["eval_role"] for row in spam} == {"phishing"}
    assert all(row["label"]["is_malicious"] for row in spam)

    sys.path.insert(0, str(ROOT / "eval"))
    import grade
    import train_phishing_classifier

    source_record = {"label": {"threat_type": "spam"}}
    assert grade.eval_role(source_record) == "phishing"
    assert grade.task_label(source_record, "phishing") == 1
    assert grade.task_label(source_record, "pi") is None
    assert train_phishing_classifier.label_for(
        source_record,
        train_phishing_classifier.PHISHING_THREAT_TYPES,
        train_phishing_classifier.DEFAULT_NEGATIVE_THREAT_TYPES,
    ) == 1


def test_judge_population_matches_manifest_text_population() -> None:
    prediction_paths = [
        ROOT / "eval/llm-judge/results/matrix/gemini_3_1_flash_lite_N1.jsonl",
        ROOT / "eval/llm-judge/results/matrix/gemini_2_5_flash_N1.jsonl",
        ROOT / "eval/llm-judge/results/matrix/gemini_3_5_flash_N1.jsonl",
    ]
    judge_ids = [
        {json.loads(line)["id"] for line in path.read_text().splitlines() if line}
        for path in prediction_paths
    ]
    rows = _rows()
    manifest_ids = {row["id"] for row in rows}
    pdf_ids = {
        row["id"]
        for row in rows
        if "pdf_attachment" in (row.get("surface") or [])
    }
    assert set.intersection(*judge_ids) == manifest_ids - pdf_ids
    assert len(manifest_ids - pdf_ids) == 5955


def test_container_bakes_and_exports_canonical_segments() -> None:
    dockerfile = (ROOT / "eval/Dockerfile").read_text()
    assert "PIGUARD_SEGMENTS=/app/eval/segments.jsonl" in dockerfile
    assert "--dump-segments --base-dir /app" in dockerfile
    assert "< eval/paper_manifest.jsonl > eval/segments.jsonl" in dockerfile


def test_gcp_defaults_only_use_registered_detector_names() -> None:
    config = (ROOT / "eval/gcp/config.env.example").read_text()
    detector_line = next(line for line in config.splitlines() if line.startswith("DETECTORS="))
    configured = detector_line.split('"', 2)[1].split()

    # hf:<model> names are dynamic; all other names must be in run_eval's registry.
    registry_source = (ROOT / "eval/run_eval.py").read_text()
    for detector in configured:
        if not detector.startswith("hf:"):
            assert f'"{detector}":' in registry_source

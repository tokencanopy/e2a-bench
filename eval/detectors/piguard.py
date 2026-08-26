"""PiguardDetector — wraps the piguard-eval Go binary.

The binary reads manifest entries from stdin (one JSON per line) and writes
prediction lines to stdout.  We batch the full manifest through a single
subprocess call so spawn overhead is paid once, not per entry.
"""
from __future__ import annotations

import json
import os
import subprocess

from .base import Prediction

_DEFAULT_BINARY = os.environ.get("PIGUARD_EVAL_BIN", "piguard-eval")


class PiguardDetector:
    def __init__(
        self,
        binary: str = _DEFAULT_BINARY,
        base_dir: str = ".",
        review_threshold: float = 0.35,
        block_threshold: float = 0.75,
    ) -> None:
        self._binary = binary
        self._base_dir = os.path.abspath(base_dir)
        self._review = review_threshold
        self._block = block_threshold

    @property
    def name(self) -> str:
        return "piguard"

    def predict(self, entry: dict) -> Prediction:
        return self.predict_batch([entry])[0]

    def predict_batch(self, entries: list[dict]) -> list[Prediction]:
        lines = "\n".join(
            json.dumps({"id": e["id"], "eml_path": e["eml_path"]}) for e in entries
        )
        try:
            result = subprocess.run(
                [
                    self._binary,
                    "--base-dir", self._base_dir,
                    "--review-threshold", str(self._review),
                    "--block-threshold", str(self._block),
                ],
                input=lines.encode(),
                capture_output=True,
                timeout=300,
            )
        except FileNotFoundError:
            return [
                Prediction(
                    id=e["id"], detector="piguard", flagged=False, score=0.0,
                    error=f"binary not found: {self._binary!r}  "
                          f"(build with: cd e2a && go build ./cmd/piguard-eval)",
                )
                for e in entries
            ]
        except subprocess.TimeoutExpired:
            return [
                Prediction(id=e["id"], detector="piguard", flagged=False, score=0.0,
                           error="timeout")
                for e in entries
            ]

        if result.returncode != 0:
            err = result.stderr.decode()[:300]
            return [
                Prediction(id=e["id"], detector="piguard", flagged=False, score=0.0,
                           error=f"exit {result.returncode}: {err}")
                for e in entries
            ]

        predictions: dict[str, Prediction] = {}
        for raw_line in result.stdout.splitlines():
            if not raw_line.strip():
                continue
            pred = json.loads(raw_line)
            predictions[pred["id"]] = Prediction(
                id=pred["id"],
                detector="piguard",
                flagged=pred.get("flagged", False),
                score=pred.get("score", 0.0),
                action=pred.get("action", "unknown"),
                categories=pred.get("categories") or [],
                latency_ms=pred.get("latency_ms", 0),
                error=pred.get("error") or None,
            )

        # Return in input order, filling gaps for any entry the binary skipped.
        out: list[Prediction] = []
        for e in entries:
            if e["id"] in predictions:
                out.append(predictions[e["id"]])
            else:
                out.append(Prediction(id=e["id"], detector="piguard",
                                      flagged=False, score=0.0,
                                      error="no output from binary"))
        return out

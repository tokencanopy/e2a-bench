from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Prediction:
    id: str
    detector: str
    flagged: bool
    score: float  # 0..1
    action: str = "unknown"
    categories: list[dict] = field(default_factory=list)
    latency_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "id": self.id,
            "detector": self.detector,
            "flagged": self.flagged,
            "score": self.score,
            "action": self.action,
            "categories": self.categories,
            "latency_ms": self.latency_ms,
        }
        if self.error is not None:
            d["error"] = self.error
        return d

    def to_jsonl_line(self) -> str:
        return json.dumps(self.to_dict())


@runtime_checkable
class Detector(Protocol):
    @property
    def name(self) -> str: ...

    def predict(self, entry: dict) -> Prediction: ...

    def predict_batch(self, entries: list[dict]) -> list[Prediction]:
        """Default: serial predict. Override for batch-optimized detectors."""
        return [self.predict(e) for e in entries]

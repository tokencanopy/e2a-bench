"""HFClassifierDetector — generic HuggingFace sequence-classification adapter.

Wraps any `AutoModelForSequenceClassification` prompt-injection classifier and
exposes the softmax probability of the injection class as a continuous score
(so AUC-ROC / AUC-PR are available, unlike API detectors that return a bare
boolean).

Validated against:
    protectai/deberta-v3-base-prompt-injection-v2   (Apache-2.0, ungated)
    leolee99/InjecGuard                              (MIT, ungated)
    fmops/distilbert-prompt-injection               (Apache-2.0, ungated)

Each model labels its classes differently (INJECTION / LABEL_1 / unsafe / ...),
so we read `config.id2label` and locate the positive class by keyword, falling
back to index 1 (the conventional positive index).

Environment:
    HF_DEVICE   force device: cuda | mps | cpu  (default: auto-detect)
    HF_HOME     HuggingFace cache dir (set this to a baked-in path in containers)
"""
from __future__ import annotations

import os
import time

from .base import Prediction
from .segment_input import content_for

# Label strings (lowercased) that indicate the positive / injection class.
_POSITIVE_MARKERS = (
    "injection", "inject", "unsafe", "malicious", "jailbreak",
    "attack", "positive", "label_1", "1",
)


def _slug(model_id: str) -> str:
    """hf:protectai/deberta-v3-base-prompt-injection-v2 -> hf_deberta_v3_base_prompt_injection_v2"""
    tail = model_id.split("/")[-1]
    return "hf_" + tail.replace("-", "_").replace(".", "_")


class HFClassifierDetector:
    def __init__(
        self,
        model_id: str,
        base_dir: str = ".",
        device: str | None = None,
        max_length: int = 512,
        batch_size: int = 32,
    ) -> None:
        self._model_id = model_id
        self._base_dir = base_dir
        self._max_length = max_length
        # HF_BATCH_SIZE lets the operator shrink batches to bound peak memory —
        # DeBERTa-v3's disentangled attention can OOM a contended MPS/GPU pool at
        # the default batch of 32 on long inputs.
        self._batch_size = int(os.environ.get("HF_BATCH_SIZE", batch_size))
        self._name = _slug(model_id)

        try:
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except ImportError as exc:
            raise ImportError(
                "Install transformers + torch: pip install 'transformers>=4.40' torch"
            ) from exc

        self._torch = torch
        self._device = device or os.environ.get("HF_DEVICE") or self._auto_device()

        # Some models (e.g. leolee99/InjecGuard a.k.a. PIGuard) ship a custom
        # architecture that requires executing repo code to load. Gate that behind
        # an explicit opt-in env var so remote code never runs silently.
        trust = os.environ.get("HF_TRUST_REMOTE_CODE", "").lower() in ("1", "true", "yes")
        self._tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=trust)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_id, trust_remote_code=trust)
        self._model.to(self._device)
        self._model.eval()

        self._pos_index = self._locate_positive_class()

    def _auto_device(self) -> str:
        t = self._torch
        if t.cuda.is_available():
            return "cuda"
        if getattr(t.backends, "mps", None) and t.backends.mps.is_available():
            return "mps"
        return "cpu"

    def _locate_positive_class(self) -> int:
        """Find the index of the injection/positive class from id2label."""
        id2label = getattr(self._model.config, "id2label", None) or {}
        # id2label keys may be ints or str ints depending on the model.
        normalized = {int(k): str(v).lower() for k, v in id2label.items()}
        for idx, label in normalized.items():
            if any(marker in label for marker in _POSITIVE_MARKERS):
                return idx
        # Fallback: conventional positive index is 1 for binary classifiers.
        return 1 if self._model.config.num_labels > 1 else 0

    @property
    def name(self) -> str:
        return self._name

    def predict(self, entry: dict) -> Prediction:
        return self.predict_batch([entry])[0]

    def predict_batch(self, entries: list[dict]) -> list[Prediction]:
        out: list[Prediction] = []
        # Stage 1: parse all texts (record parse errors, keep alignment).
        texts: list[str | None] = []
        for e in entries:
            try:
                texts.append(content_for(e, self._base_dir))
            except Exception as exc:
                texts.append(None)
                e["_parse_error"] = f"parse: {exc}"

        # Stage 2: run inference in mini-batches over the successfully parsed texts.
        torch = self._torch
        for start in range(0, len(entries), self._batch_size):
            chunk = entries[start:start + self._batch_size]
            chunk_texts = texts[start:start + self._batch_size]

            valid = [(i, t) for i, t in enumerate(chunk_texts) if t is not None]
            scores_by_local: dict[int, float] = {}
            latency_ms = 0
            if valid:
                batch_input = [t for _, t in valid]
                t0 = time.monotonic()
                enc = self._tokenizer(
                    batch_input,
                    return_tensors="pt",
                    truncation=True,
                    max_length=self._max_length,
                    padding=True,
                ).to(self._device)
                with torch.no_grad():
                    logits = self._model(**enc).logits
                    probs = torch.softmax(logits, dim=-1)
                pos = probs[:, self._pos_index].tolist()
                # amortize batch latency across its members
                latency_ms = int((time.monotonic() - t0) * 1000 / max(len(valid), 1))
                for (local_i, _), p in zip(valid, pos):
                    scores_by_local[local_i] = float(p)

            for local_i, e in enumerate(chunk):
                if "_parse_error" in e:
                    out.append(Prediction(
                        id=e["id"], detector=self._name, flagged=False,
                        score=0.0, error=e.pop("_parse_error")))
                    continue
                score = scores_by_local.get(local_i, 0.0)
                flagged = score >= 0.5  # model's own decision boundary
                action = "allow"
                if score >= 0.75:
                    action = "block"
                elif score >= 0.35:
                    action = "review"
                out.append(Prediction(
                    id=e["id"], detector=self._name, flagged=flagged,
                    score=score, action=action, latency_ms=latency_ms))
        return out

"""GCGPerplexityDetector — local LM detector for mixed real GCG suffixes.

This detector targets the class of GCG suffixes that the cheap symbol-heavy
heuristic intentionally misses: suffixes that combine alphabetic fragments,
programming tokens, punctuation, and abrupt low-probability text after an
otherwise ordinary email body.

It uses a small causal language model to compare token-level negative
log-likelihood in the message tail against the preceding context. The detector
is local and batchable, but requires transformers + torch and a downloaded model.
"""
from __future__ import annotations

import json
import math
import os
import re
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

from .base import Prediction
from .gcg_suffix import Segment, _extract_segments

DEFAULT_MODEL = "distilbert/distilgpt2"
DEFAULT_THRESHOLDS = Path(__file__).with_name("gcg_perplexity_thresholds.json")
_URL_RE = re.compile(r"https?://|www\.|[A-Za-z0-9.-]+\.(?:com|org|net|edu|gov)\b", re.I)
_BULK_RE = re.compile(r"\b(unsubscribe|opt[ -]?out|click here|privacy policy|remove me)\b", re.I)
_HTML_ARTIFACT_RE = re.compile(r"&(?:nbsp|lt|gt|amp|quot);|</?[a-z][a-z0-9]*(?:\s|>|/)", re.I)


@dataclass(frozen=True)
class PerplexityEvidence:
    score: float
    raw_score: float
    suffix_mean_nll: float
    prefix_mean_nll: float
    suffix_max_nll: float
    suffix_high_nll_ratio: float
    window_tokens: int
    segment_kind: str
    indirect: bool


def _sigmoid(value: float) -> float:
    if value >= 40:
        return 1.0
    if value <= -40:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return float(ordered[idx])


def _compact_text(text: str) -> str:
    return " ".join(text.strip().split())


class GCGPerplexityDetector:
    def __init__(
        self,
        base_dir: str = ".",
        model_id: str = DEFAULT_MODEL,
        thresholds_path: str | None = None,
        review_threshold: float | None = None,
        block_threshold: float | None = None,
        batch_size: int = 8,
        max_length: int = 256,
        device: str | None = None,
    ) -> None:
        self._base_dir = base_dir
        self._model_id = model_id
        self._batch_size = batch_size
        self._max_length = max_length
        self._tail_windows = (24, 32, 48, 64)
        self._prefix_window = 64
        self._max_segment_chars = 2400
        self._max_segments_per_message = 4
        self._score_center = 1.4
        self._score_scale = 0.65
        self._review_threshold = 0.35 if review_threshold is None else review_threshold
        self._block_threshold = 0.75 if block_threshold is None else block_threshold

        self._load_thresholds(thresholds_path)
        if review_threshold is not None:
            self._review_threshold = review_threshold
        if block_threshold is not None:
            self._block_threshold = block_threshold

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise ImportError(
                "Install transformers + torch: pip install -r eval/requirements.txt"
            ) from exc

        self._torch = torch
        self._device = device or os.environ.get("HF_DEVICE") or self._auto_device()
        self._tokenizer = AutoTokenizer.from_pretrained(model_id)
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token
        self._model = AutoModelForCausalLM.from_pretrained(model_id)
        self._model.to(self._device)
        self._model.eval()

    def _load_thresholds(self, path: str | None) -> None:
        if path == "":
            return
        threshold_path = Path(path) if path else DEFAULT_THRESHOLDS
        if not threshold_path.exists():
            return
        data = json.loads(threshold_path.read_text())
        if data.get("model_id") and data["model_id"] != self._model_id:
            return
        self._review_threshold = float(data.get("review_threshold", self._review_threshold))
        self._block_threshold = float(data.get("block_threshold", self._block_threshold))
        self._score_center = float(data.get("score_center", self._score_center))
        self._score_scale = float(data.get("score_scale", self._score_scale))
        self._tail_windows = tuple(data.get("tail_windows", self._tail_windows))
        self._prefix_window = int(data.get("prefix_window", self._prefix_window))

    def _auto_device(self) -> str:
        t = self._torch
        if t.cuda.is_available():
            return "cuda"
        if getattr(t.backends, "mps", None) and t.backends.mps.is_available():
            return "mps"
        return "cpu"

    @property
    def name(self) -> str:
        return "gcg_perplexity"

    def _empty_evidence(self) -> PerplexityEvidence:
        return PerplexityEvidence(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, "", False)

    def _score_from_raw(self, raw_score: float) -> float:
        scale = max(self._score_scale, 1e-6)
        return _sigmoid((raw_score - self._score_center) / scale)

    def _segment_texts(self, entry: dict) -> list[Segment]:
        segments = _extract_segments(entry["eml_path"], self._base_dir)
        out: list[Segment] = []
        for segment in segments:
            if segment.kind in {"from", "reply-to", "to"}:
                continue
            text = _compact_text(segment.text)
            if len(text) > self._max_segment_chars:
                text = text[-self._max_segment_chars:]
            if len(text) >= 80 or segment.kind == "subject":
                out.append(Segment(segment.kind, text, segment.indirect))
            if len(out) >= self._max_segments_per_message:
                break
        return out

    def _nll_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        torch = self._torch
        enc = self._tokenizer(
            texts,
            return_tensors="pt",
            truncation=True,
            max_length=self._max_length,
            padding=True,
        ).to(self._device)
        with torch.no_grad():
            logits = self._model(**enc).logits
        shift_logits = logits[:, :-1, :].contiguous()
        shift_labels = enc["input_ids"][:, 1:].contiguous()
        shift_mask = enc["attention_mask"][:, 1:].contiguous()
        losses = torch.nn.functional.cross_entropy(
            shift_logits.view(-1, shift_logits.size(-1)),
            shift_labels.view(-1),
            reduction="none",
        ).view(shift_labels.size())

        out: list[list[float]] = []
        for row_loss, row_mask in zip(losses, shift_mask):
            valid = row_mask.bool()
            out.append([float(v) for v in row_loss[valid].detach().cpu().tolist()])
        return out

    def _score_nlls(
        self,
        nlls: list[float],
        segment: Segment,
    ) -> PerplexityEvidence:
        best = self._empty_evidence()
        n = len(nlls)
        if n < 32:
            return best
        for window in self._tail_windows:
            if n <= window + 8:
                continue
            suffix = nlls[-window:]
            prefix_start = max(0, n - window - self._prefix_window)
            prefix = nlls[prefix_start:-window]
            if len(prefix) < 8:
                continue
            suffix_mean = statistics.fmean(suffix)
            prefix_mean = statistics.fmean(prefix)
            suffix_max = max(suffix)
            suffix_p90 = _percentile(suffix, 0.90)
            prefix_p90 = _percentile(prefix, 0.90)
            high_ratio = sum(v >= max(7.5, prefix_p90 + 1.0) for v in suffix) / len(suffix)
            raw = (
                (suffix_mean - prefix_mean)
                + 0.18 * (suffix_p90 - prefix_p90)
                + 1.35 * high_ratio
                + 0.04 * max(0.0, suffix_max - 9.0)
            )
            tail_text = segment.text[-500:]
            if _URL_RE.search(tail_text):
                raw *= 0.58
            if _BULK_RE.search(tail_text):
                raw *= 0.55
            if _HTML_ARTIFACT_RE.search(tail_text):
                raw *= 0.70
            score = self._score_from_raw(raw)
            if score > best.score:
                best = PerplexityEvidence(
                    score=score,
                    raw_score=raw,
                    suffix_mean_nll=suffix_mean,
                    prefix_mean_nll=prefix_mean,
                    suffix_max_nll=suffix_max,
                    suffix_high_nll_ratio=high_ratio,
                    window_tokens=window,
                    segment_kind=segment.kind,
                    indirect=segment.indirect or segment.kind == "attachment",
                )
        return best

    def _action(self, score: float) -> str:
        if score >= self._block_threshold:
            return "block"
        if score >= self._review_threshold:
            return "review"
        return "allow"

    def predict(self, entry: dict) -> Prediction:
        return self.predict_batch([entry])[0]

    def predict_batch(self, entries: list[dict]) -> list[Prediction]:
        started = time.monotonic()
        parsed: list[tuple[int, Segment] | None] = []
        errors: dict[int, str] = {}
        texts: list[str] = []
        for entry_i, entry in enumerate(entries):
            try:
                segments = self._segment_texts(entry)
            except Exception as exc:
                errors[entry_i] = f"parse: {exc}"
                continue
            if not segments:
                parsed.append(None)
                texts.append("")
                continue
            for segment in segments:
                parsed.append((entry_i, segment))
                texts.append(segment.text)

        best_by_entry: dict[int, PerplexityEvidence] = {
            i: self._empty_evidence() for i in range(len(entries))
        }
        for start in range(0, len(texts), self._batch_size):
            chunk = texts[start:start + self._batch_size]
            chunk_meta = parsed[start:start + self._batch_size]
            valid_pairs = [
                (local_i, text, chunk_meta[local_i])
                for local_i, text in enumerate(chunk)
                if text and chunk_meta[local_i] is not None
            ]
            if not valid_pairs:
                continue
            nll_rows = self._nll_batch([text for _, text, _ in valid_pairs])
            for (_, _, meta), nlls in zip(valid_pairs, nll_rows):
                assert meta is not None
                entry_i, segment = meta
                evidence = self._score_nlls(nlls, segment)
                if evidence.score > best_by_entry[entry_i].score:
                    best_by_entry[entry_i] = evidence

        latency_ms = int((time.monotonic() - started) * 1000 / max(len(entries), 1))
        predictions: list[Prediction] = []
        for entry_i, entry in enumerate(entries):
            if entry_i in errors:
                predictions.append(Prediction(
                    id=entry["id"],
                    detector=self.name,
                    flagged=False,
                    score=0.0,
                    action="allow",
                    latency_ms=latency_ms,
                    error=errors[entry_i],
                ))
                continue
            evidence = best_by_entry[entry_i]
            flagged = evidence.score >= self._review_threshold
            categories = [{
                "name": (
                    "prompt_injection_indirect"
                    if evidence.indirect
                    else "prompt_injection_direct"
                ),
                "score": round(evidence.score, 4),
                "native_code": "gcg_perplexity",
            }, {
                "name": "perplexity_tail_anomaly",
                "score": round(evidence.score, 4),
                "native_code": "tail_nll_delta",
                "raw_score": round(evidence.raw_score, 4),
                "segment": evidence.segment_kind,
                "window_tokens": evidence.window_tokens,
                "suffix_mean_nll": round(evidence.suffix_mean_nll, 4),
                "prefix_mean_nll": round(evidence.prefix_mean_nll, 4),
                "suffix_max_nll": round(evidence.suffix_max_nll, 4),
                "suffix_high_nll_ratio": round(evidence.suffix_high_nll_ratio, 4),
            }]
            predictions.append(Prediction(
                id=entry["id"],
                detector=self.name,
                flagged=flagged,
                score=evidence.score,
                action=self._action(evidence.score),
                categories=categories,
                latency_ms=latency_ms,
            ))
        return predictions

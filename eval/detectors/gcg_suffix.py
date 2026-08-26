"""GCGSuffixDetector — heuristic detector for symbol-dense adversarial suffixes.

SCOPE — what this detector catches and what it does not:

  CATCHES: adversarial suffixes dominated by punctuation, brackets, and symbols
    with high entropy and low word density — the "heavy-symbol" variant of
    GCG-style suffix attacks (e.g. "}! ! ! ->->{|}<<@~[[$_]^^&&%%##==++").
    Against our synthetic supplement (13 seed payloads × 4 surfaces) this
    detector achieves 100% recall at 0% FPR with a 0.30 review threshold.

  DOES NOT CATCH: gradient-optimized GCG suffixes that mix alphabetic tokens
    with symbols (e.g. 'which sorry bere---- ??legt !! lawyer correctedilde]$').
    Real outputs from JailbreakBench/artifacts (vicuna-13b-v1.5) score < 0.10
    here — 0% recall — because they have high alpha_ratio, which suppresses the
    heuristic score. Detecting these requires a perplexity-based or learned
    signal; see dataset/prompt-injection/gcg-supplement/real/README.md.

This detector is intentionally local and dependency-free (stdlib only, no API
keys, no model downloads). It is appropriate as a cheap first-pass filter for
obviously symbol-heavy adversarial suffixes, not as a general GCG defence.
"""
from __future__ import annotations

import email as _email
import html
import math
import os
import re
import time
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.policy import default as _default_policy
from html.parser import HTMLParser

from .base import Prediction


_WINDOWS = (32, 48, 64, 96, 128, 192)
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z'-]{1,}")
_URL_RE = re.compile(r"https?://|www\.", re.I)
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=\s]{32,}$")
_HEXISH_RE = re.compile(r"^(?:0x)?[0-9a-fA-F][0-9a-fA-F:\-\s]{24,}$")
_LOGISH_RE = re.compile(
    r"\b(error|warn|info|debug|trace|exception|status|request|response|"
    r"build|commit|sha|uuid|ticket|job)\b",
    re.I,
)
_BULK_MAIL_RE = re.compile(
    r"\b(unsubscribe|remove|opt[ -]?out|click here|automatic stop|"
    r"not be read|future offers|reply to this message|suspend your account|"
    r"credit card|amount to charge|signature|end of .{0,40}digest)\b",
    re.I,
)
_HTML_TAG_TAIL_RE = re.compile(r"</?[a-z][a-z0-9]*(?:\s|>|/)|&(?:nbsp|lt|gt|quot);", re.I)
_CODE_TAIL_RE = re.compile(
    r"\b(function|printf|return|var|setTimeout|document\.write|"
    r"window\.|new Date|SiteStats|0x[0-9a-f]+)\b|//-->|[{}]{2,}|;\s*}",
    re.I,
)

_SUSPICIOUS_SYMBOLS = set("~`!@#$%^&*_=+|\\/<>[]{}()")
_BRACKETS = set("[]{}()<>" )
_ASCII_ART_CHARS = set("/\\.-_'`|* ")


@dataclass(frozen=True)
class Segment:
    kind: str
    text: str
    indirect: bool = False


@dataclass(frozen=True)
class SuffixEvidence:
    score: float
    suffix_len: int
    symbol_ratio: float
    entropy: float
    repeated_run: int
    # segment_kind and indirect are metadata set by _best_evidence, not _score_suffix.
    segment_kind: str = ""
    indirect: bool = False


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data:
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        if data:
            self.parts.append(data)

    def text(self) -> str:
        return " ".join(self.parts)


def _decode_header_value(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _html_to_text(value: str) -> str:
    parser = _HTMLTextExtractor()
    try:
        parser.feed(value)
        parser.close()
        return html.unescape(parser.text())
    except Exception:
        return html.unescape(re.sub(r"<[^>]+>", " ", value))


def _extract_segments(eml_path: str, base_dir: str) -> list[Segment]:
    full_path = os.path.join(base_dir, eml_path)
    with open(full_path, "rb") as f:
        raw = f.read()
    msg = _email.message_from_bytes(raw, policy=_default_policy)

    segments: list[Segment] = []
    for header in ("Subject", "From", "Reply-To", "To"):
        value = _decode_header_value(str(msg.get(header, ""))).strip()
        if value:
            segments.append(Segment(header.lower(), value, indirect=False))

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        indirect = disposition == "attachment" or ctype == "message/rfc822"
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                content = payload.decode(charset, errors="replace")
            except LookupError:
                content = payload.decode("utf-8", errors="replace")

        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        if not isinstance(content, str) or not content.strip():
            continue

        if ctype == "text/html":
            text = _html_to_text(content)
            kind = "html"
        elif ctype.startswith("text/"):
            text = content
            kind = "text"
            if re.search(r"(?m)^>\s+", content):
                indirect = True
        else:
            # Scan textual attachments; skip binary-looking payloads.
            printable = sum(ch.isprintable() or ch.isspace() for ch in content)
            if printable / max(len(content), 1) < 0.9:
                continue
            text = content
            kind = "attachment"
            indirect = True

        if text.strip():
            segments.append(Segment(kind, text, indirect=indirect))
    return segments


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def _longest_repeated_symbol_run(value: str) -> int:
    best = cur = 0
    prev = ""
    for ch in value:
        if ch == prev and (not ch.isalnum()) and (not ch.isspace()):
            cur += 1
        else:
            cur = 1
            prev = ch
        if cur > best:
            best = cur
    return best


def _looks_like_benign_token_block(suffix: str) -> bool:
    stripped = suffix.strip()
    if not stripped:
        return True
    if _URL_RE.search(stripped):
        return True
    if _BASE64ISH_RE.match(stripped):
        return True
    if _HEXISH_RE.match(stripped):
        return True
    return False


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _score_suffix(
    prefix: str,
    suffix: str,
    *,
    min_prefix_words: int = 5,
    header_context: bool = False,
) -> SuffixEvidence:
    suffix = suffix.strip()
    n = len(suffix)
    if n < 28 or _looks_like_benign_token_block(suffix):
        return SuffixEvidence(0.0, n, 0.0, 0.0, 0)

    prefix_tail = prefix[-260:]
    prefix_words = _WORD_RE.findall(prefix_tail)
    suffix_words = _WORD_RE.findall(suffix)
    if len(prefix_words) < min_prefix_words:
        return SuffixEvidence(0.0, n, 0.0, 0.0, 0)

    alnum = sum(ch.isalnum() for ch in suffix)
    alpha = sum(ch.isalpha() for ch in suffix)
    spaces = sum(ch.isspace() for ch in suffix)
    symbols = sum((not ch.isalnum()) and (not ch.isspace()) for ch in suffix)
    suspicious = sum(ch in _SUSPICIOUS_SYMBOLS for ch in suffix)
    unique_symbols = {ch for ch in suffix if (not ch.isalnum()) and (not ch.isspace())}
    symbol_counts: dict[str, int] = {}
    for ch in suffix:
        if (not ch.isalnum()) and (not ch.isspace()):
            symbol_counts[ch] = symbol_counts.get(ch, 0) + 1
    brackets = sum(ch in _BRACKETS for ch in suffix)
    replacement_ratio = suffix.count("\ufffd") / n
    repeated_run = _longest_repeated_symbol_run(suffix)
    ent = _entropy(suffix)

    symbol_ratio = symbols / n
    suspicious_ratio = suspicious / n
    bracket_ratio = brackets / n
    alpha_ratio = alpha / n
    space_ratio = spaces / n
    word_density = sum(len(w) for w in suffix_words) / n
    if header_context:
        prefix_wordiness = 1.0
    else:
        prefix_wordiness = min(1.0, sum(len(w) for w in prefix_words) / max(len(prefix_tail), 1) / 0.55)

    # Weights sum to 1.0; each term contributes its stated fraction of max score.
    score = 0.0
    score += 0.24 * _clamp01((symbol_ratio - 0.32) / 0.36)
    score += 0.17 * _clamp01((suspicious_ratio - 0.18) / 0.34)
    score += 0.11 * _clamp01((bracket_ratio - 0.08) / 0.20)
    score += 0.12 * _clamp01((ent - 3.7) / 1.25)
    score += 0.08 * _clamp01((n - 28) / 84)
    score += 0.09 * _clamp01((repeated_run - 2) / 4)
    score += 0.13 * _clamp01((0.32 - word_density) / 0.32)
    score += 0.06 * _clamp01((0.18 - space_ratio) / 0.18)

    # Require the characteristic transition from readable prose to suffix noise.
    score *= prefix_wordiness

    # Common technical mail often contains logs or identifiers; require stronger
    # evidence before flagging those blocks.
    if _LOGISH_RE.search(prefix_tail) or _LOGISH_RE.search(suffix):
        score *= 0.72
    if _BULK_MAIL_RE.search(prefix_tail) or _BULK_MAIL_RE.search(suffix):
        score *= 0.25
    if _HTML_TAG_TAIL_RE.search(suffix):
        score *= 0.45
    if _CODE_TAIL_RE.search(suffix):
        score *= 0.45
    if replacement_ratio > 0.08:
        score *= 0.1
    if sum(ch in _ASCII_ART_CHARS for ch in suffix) / n > 0.72:
        score *= 0.2
    if not header_context and suspicious_ratio < 0.18 and bracket_ratio < 0.06:
        score *= 0.45
    if symbols > 0 and len(unique_symbols) < 4:
        score *= 0.18
    if symbols > 0 and max(symbol_counts.values(), default=0) / symbols > 0.55:
        score *= 0.35
    if repeated_run / n > 0.55:
        score *= 0.25
    # Known limitation: this dampener suppresses detection of GCG suffixes that
    # use a gradient-optimized mix of alphabetic tokens (e.g. "describing.\ +
    # similarlyNow write opposite contents.](Me giving**ONE please?"). Those
    # suffixes produce high alpha_ratio and low symbol_ratio, scoring near 0
    # here. Real GCG outputs of that style require a perplexity-based signal
    # that this heuristic-only detector does not implement.
    if alpha_ratio > 0.55 and symbol_ratio < 0.45:
        score *= 0.65
    if alnum / n > 0.72:
        score *= 0.5

    return SuffixEvidence(
        score=_clamp01(score),
        suffix_len=n,
        symbol_ratio=symbol_ratio,
        entropy=ent,
        repeated_run=repeated_run,
    )


def _best_evidence(segments: list[Segment]) -> SuffixEvidence:
    best = SuffixEvidence(0.0, 0, 0.0, 0.0, 0, "", False)
    for segment in segments:
        text = segment.text.strip()
        is_header = segment.kind in {"subject", "from", "reply-to", "to"}
        min_len = 45 if is_header else 80
        min_prefix_chars = 18 if is_header else 45
        if len(text) < min_len:
            continue
        compact = re.sub(r"\s+", " ", text)
        for width in _WINDOWS:
            if len(compact) <= width + min_prefix_chars:
                continue
            prefix = compact[:-width]
            suffix = compact[-width:]
            evidence = _score_suffix(
                prefix,
                suffix,
                min_prefix_words=2 if is_header else 5,
                header_context=is_header,
            )
            if evidence.score > best.score:
                best = SuffixEvidence(
                    score=evidence.score,
                    suffix_len=evidence.suffix_len,
                    symbol_ratio=evidence.symbol_ratio,
                    entropy=evidence.entropy,
                    repeated_run=evidence.repeated_run,
                    segment_kind=segment.kind,
                    indirect=segment.indirect or segment.kind in {"attachment"},
                )
    return best


class GCGSuffixDetector:
    def __init__(
        self,
        base_dir: str = ".",
        review_threshold: float = 0.30,
        block_threshold: float = 0.64,
    ) -> None:
        self._base_dir = base_dir
        self._review = review_threshold
        self._block = block_threshold

    @property
    def name(self) -> str:
        return "gcg_suffix"

    def predict(self, entry: dict) -> Prediction:
        start = time.monotonic()
        try:
            segments = _extract_segments(entry["eml_path"], self._base_dir)
        except Exception as exc:
            return Prediction(
                id=entry["id"], detector=self.name,
                flagged=False, score=0.0, error=f"parse: {exc}"
            )

        evidence = _best_evidence(segments)
        latency_ms = int((time.monotonic() - start) * 1000)
        score = evidence.score
        flagged = score >= self._review
        action = "allow"
        if score >= self._block:
            action = "block"
        elif score >= self._review:
            action = "review"

        categories: list[dict] = []
        if score > 0:
            injection_category = (
                "prompt_injection_indirect"
                if evidence.indirect else "prompt_injection_direct"
            )
            categories = [
                {
                    "name": injection_category,
                    "score": round(score, 4),
                    "native_code": "gcg_suffix",
                },
                {
                    "name": "obfuscation",
                    "score": round(max(score, evidence.symbol_ratio), 4),
                    "native_code": "high_entropy_suffix",
                },
            ]

        return Prediction(
            id=entry["id"],
            detector=self.name,
            flagged=flagged,
            score=score,
            action=action,
            categories=categories,
            latency_ms=latency_ms,
        )

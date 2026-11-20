"""Overlap-safe masking engine with label and deterministic hash modes."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import TextIO

from .rules import RULES, Rule

_MODES = ("label", "hash")
_KEY_START = "-----BEGIN "
_KEY_END = "-----END "
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


@dataclass(frozen=True, slots=True)
class _Occurrence:
    start: int
    end: int
    match: re.Match[str]
    rule: Rule


def _keep_line_breaks(original: str, replacement: str) -> str:
    return replacement + "".join(_LINE_BREAK.findall(original))


def merge_stats(target: dict[str, int], addition: dict[str, int]) -> dict[str, int]:
    """Add per-rule counters in place and return the target."""
    for name, count in addition.items():
        target[name] = target.get(name, 0) + count
    return target


class Masker:
    """Replace detected values with stable labels or keyed HMAC digests."""

    def __init__(self, mode: str = "label", key: bytes | None = None) -> None:
        if mode not in _MODES:
            raise ValueError(f"desteklenmeyen mod: {mode}")
        if mode == "hash" and not key:
            raise ValueError("hash modu için anahtar gerekli")
        self.mode = mode
        self._key = key

    def mask(self, text: str) -> str:
        """Return a masked copy of the whole text."""
        return self.mask_with_stats(text)[0]

    def mask_with_stats(self, text: str) -> tuple[str, dict[str, int]]:
        """Mask text and return the output together with per-rule counts."""
        pieces: list[str] = []
        stats: dict[str, int] = {}
        cursor = 0
        for occurrence in self._collect(text):
            pieces.append(text[cursor : occurrence.start])
            pieces.append(self._replacement(occurrence))
            cursor = occurrence.end
            stats[occurrence.rule.name] = stats.get(occurrence.rule.name, 0) + 1
        pieces.append(text[cursor:])
        return "".join(pieces), stats

    def _collect(self, text: str) -> list[_Occurrence]:
        candidates: list[_Occurrence] = []
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                value = match.group(0)
                if rule.validate(value):
                    candidates.append(_Occurrence(match.start(), match.end(), match, rule))
        candidates.sort(key=lambda item: (item.start, item.rule.priority, -(item.end - item.start)))
        chosen: list[_Occurrence] = []
        occupied_until = 0
        for candidate in candidates:
            if candidate.start < occupied_until:
                continue
            chosen.append(candidate)
            occupied_until = candidate.end
        return chosen

    def _replacement(self, occurrence: _Occurrence) -> str:
        value = occurrence.match.group(0)
        label = occurrence.rule.label
        token = label(occurrence.match) if callable(label) else label
        if self.mode == "hash":
            message = occurrence.rule.name.encode("utf-8") + b":" + value.encode("utf-8")
            digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()[:16]
            token = f"[{occurrence.rule.name.upper()}:{digest}]"
        return _keep_line_breaks(value, token)


def mask_stream(source: TextIO, sink: TextIO, masker: Masker) -> dict[str, int]:
    """Mask line by line, buffering only while inside a multi-line PEM block."""
    stats: dict[str, int] = {}
    buffer: list[str] = []
    for line in source:
        if buffer:
            buffer.append(line)
            if _KEY_END in line:
                masked, counts = masker.mask_with_stats("".join(buffer))
                sink.write(masked)
                merge_stats(stats, counts)
                buffer.clear()
            continue
        if _KEY_START in line and _KEY_END not in line:
            buffer.append(line)
            continue
        masked, counts = masker.mask_with_stats(line)
        sink.write(masked)
        merge_stats(stats, counts)
    if buffer:
        masked, counts = masker.mask_with_stats("".join(buffer))
        sink.write(masked)
        merge_stats(stats, counts)
    return stats

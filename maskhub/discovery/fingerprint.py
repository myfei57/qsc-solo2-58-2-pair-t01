"""Statistical shape fingerprints for columns.

A fingerprint captures *what values look like* without storing any of them:
bucketed length/cardinality statistics plus the distribution of masked shape
patterns (``alice@example.com`` -> ``aaaaa@aaaaaaa.aaa``). Two fingerprints
with the same signature describe the same shape, so a later scan can decide
whether a column actually changed instead of re-deciding every time.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass

_CJK = re.compile(r"[一-鿿㐀-䶿]")
_DIGIT = re.compile(r"\d")
_LETTER = re.compile(r"[A-Za-z]")
_SAMPLE_CAP = 1000


def _bucket_step(value: float, step: float) -> float:
    return round(round(value / step) * step, 4)


def _length_bucket(length: int) -> tuple[str, ...]:
    if length == 0:
        return ("empty",)
    # coarse non-overlapping buckets, deliberately wide at the boundaries
    # where real values of one shape fluctuate (emails 10..24 chars)
    if length <= 5:
        return ("tiny",)
    if length <= 7:
        return ("short",)
    if length <= 25:
        return ("word",)
    if length <= 45:
        return ("medium",)
    return ("long",)


def _length_buckets_for(non_empty_values: list[str]) -> dict[str, float]:
    counts: dict[str, int] = {}
    for value in non_empty_values:
        for bucket in _length_bucket(len(value)):
            counts[bucket] = counts.get(bucket, 0) + 1
    n = len(non_empty_values)
    # presence-only signature: which coarse buckets are represented. Shares
    # depend on the exact sampled mix and are kept out of the signature.
    return dict(sorted((key, 1.0) for key, count in counts.items() if count / n >= 0.25))


def shape_of(value: str) -> str:
    """Collapse a value into a run-length shape token."""

    chars: list[str] = []
    previous = ""
    for ch in value:
        if _CJK.match(ch):
            kind = "C"
        elif _DIGIT.match(ch):
            kind = "9"
        elif _LETTER.match(ch):
            kind = "a"
        elif ch.isspace():
            kind = " "
        else:
            kind = ch  # punctuation stays literal, so separators are visible
        if kind != previous:
            chars.append(kind)
        previous = kind
    return "".join(chars)


@dataclass(frozen=True)
class ColumnFingerprint:
    total: int
    sampled: int
    non_empty: int
    unique_ratio: float
    empty_ratio: float
    digit_ratio: float
    letter_ratio: float
    cjk_ratio: float
    mean_length: float
    length_buckets: dict[str, float]
    shape_patterns: dict[str, float]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "ColumnFingerprint | None":
        if not isinstance(payload, dict):
            return None
        try:
            return cls(
                total=int(payload["total"]),
                sampled=int(payload["sampled"]),
                non_empty=int(payload["non_empty"]),
                unique_ratio=float(payload["unique_ratio"]),
                empty_ratio=float(payload["empty_ratio"]),
                digit_ratio=float(payload["digit_ratio"]),
                letter_ratio=float(payload["letter_ratio"]),
                cjk_ratio=float(payload["cjk_ratio"]),
                mean_length=float(payload["mean_length"]),
                length_buckets={
                    str(key): float(value)
                    for key, value in dict(payload["length_buckets"]).items()
                },
                shape_patterns={
                    str(key): float(value)
                    for key, value in dict(payload["shape_patterns"]).items()
                },
            )
        except (KeyError, TypeError, ValueError):
            return None

    def signature(self) -> str:
        # Coarse on the large ratios (0.05 buckets) but precise on length and
        # on the dominant shape patterns, so structurally different columns
        # (emails vs phone numbers) cannot collapse onto one signature.
        top_patterns = {
            key: _bucket_step(value, 0.25)
            for key, value in sorted(
                self.shape_patterns.items(), key=lambda pair: (-pair[1], pair[0])
            )
            if _bucket_step(value, 0.25) >= 0.5
        }
        # length buckets are presence-only (shares are sampling noise)
        dominant_lengths = sorted(key for key, value in self.length_buckets.items() if value > 0)
        canonical = {
            "sampled_bucket": _bucket_step(min(self.sampled, _SAMPLE_CAP) / _SAMPLE_CAP, 0.1),
            "unique": (
                "low" if self.unique_ratio < 0.5
                else "half" if self.unique_ratio < 0.9 else "high"
            ),
            "empty": _bucket_step(self.empty_ratio, 0.1),
            "digit": _bucket_step(self.digit_ratio, 0.1),
            "letter": _bucket_step(self.letter_ratio, 0.1),
            "cjk": _bucket_step(self.cjk_ratio, 0.1),
            "mean_len": round(self.mean_length / 60.0, 1),
            "has_cjk": self.cjk_ratio >= 0.5,
            "pure_digit": self.digit_ratio >= 0.95 and self.letter_ratio < 0.05,
            "pure_letter": self.letter_ratio >= 0.95 and self.digit_ratio < 0.05,
            "length_buckets": dominant_lengths,
            "shape_patterns": top_patterns,
        }
        import json

        raw = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def fingerprint_values(values: list[object]) -> ColumnFingerprint:
    samples = [str(item).strip() for item in values[:_SAMPLE_CAP] if item is not None]
    total = len(values)
    sampled = len(values[:_SAMPLE_CAP])
    non_empty_values = [item for item in samples if item]
    non_empty = len(non_empty_values)
    empty = sampled - non_empty

    digit_hits = letter_hits = cjk_hits = 0
    length_sum = 0
    shape_buckets: dict[str, int] = {}
    for value in non_empty_values:
        if _DIGIT.search(value):
            digit_hits += 1
        if _LETTER.search(value):
            letter_hits += 1
        if _CJK.search(value):
            cjk_hits += 1
        length_sum += len(value)
        shape = shape_of(value)
        shape_buckets[shape] = shape_buckets.get(shape, 0) + 1

    unique_ratio = len(set(non_empty_values)) / non_empty if non_empty else 0.0
    length_buckets = _length_buckets_for(non_empty_values)

    def ratio(numerator: int) -> float:
        return round(numerator / non_empty, 3) if non_empty else 0.0

    return ColumnFingerprint(
        total=total,
        sampled=sampled,
        non_empty=non_empty,
        unique_ratio=round(unique_ratio, 3),
        empty_ratio=round(empty / sampled, 3) if sampled else 0.0,
        digit_ratio=ratio(digit_hits),
        letter_ratio=ratio(letter_hits),
        cjk_ratio=ratio(cjk_hits),
        mean_length=round(length_sum / non_empty, 2) if non_empty else 0.0,
        length_buckets=dict(sorted(length_buckets.items())),
        shape_patterns={
            key: _bucket_step(count / non_empty, 0.05)
            for key, count in sorted(shape_buckets.items(), key=lambda pair: (-pair[1], pair[0]))
        },
    )

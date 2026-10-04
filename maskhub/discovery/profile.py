"""Column profiling and the stable shape fingerprint.

The profiler receives already-extracted sample values: the gateway never
fetches or stores source rows itself. Only coarse shape statistics are kept;
individual values are discarded as soon as the fingerprint is computed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ColumnProfile:
    field_name: str
    total: int
    non_null: int
    distinct: int
    avg_length: float
    numeric_ratio: float
    alpha_ratio: float
    alnum_ratio: float
    max_length: int

    @property
    def distinct_ratio(self) -> float:
        return self.distinct / self.non_null if self.non_null else 0.0

    @property
    def avg_length_bucket(self) -> int:
        # Round to 4-character bands so a couple of longer rows does not
        # invalidate an otherwise identical column shape.
        if not self.non_null:
            return 0
        return int(self.avg_length // 4) * 4

    def fingerprint(self) -> str:
        """Coarse shape signature, stable across normal row-level churn."""

        material = {
            "non_null_ratio": _bucket_ratio(self.non_null / self.total if self.total else 0.0),
            "distinct_ratio": _bucket_ratio(self.distinct_ratio),
            "avg_length": self.avg_length_bucket,
            "max_length": _length_bucket(self.max_length),
            "numeric": _bucket_ratio(self.numeric_ratio),
            "alpha": _bucket_ratio(self.alpha_ratio),
            "alnum": _bucket_ratio(self.alnum_ratio),
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _bucket_ratio(value: float) -> int:
    # Quantise to 10% bands; small sampling noise keeps the same bucket.
    return round(min(1.0, max(0.0, value)) * 10)


def _length_bucket(value: int) -> int:
    # Powers-of-two-ish bands with padded boundaries so normal one-character
    # variation near a threshold does not flip the fingerprint.
    if value <= 0:
        return 0
    if value <= 12:
        return 12
    if value <= 24:
        return 24
    if value <= 40:
        return 40
    if value <= 64:
        return 64
    if value <= 128:
        return 128
    return 256 if value <= 256 else 512


def _is_null(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def profile_column(field_name: str, values: list[object]) -> ColumnProfile:
    total = len(values)
    seen: set[str] = set()
    lengths: list[int] = []
    numeric = alpha = alnum = 0

    for value in values:
        if _is_null(value):
            continue
        text = value if isinstance(value, str) else str(value)
        text = text.strip()
        seen.add(text)
        lengths.append(len(text))
        if text.isdigit():
            numeric += 1
        elif text.isalpha():
            alpha += 1
        elif text.isalnum():
            alnum += 1

    non_null = len(lengths)
    avg_length = sum(lengths) / non_null if non_null else 0.0
    return ColumnProfile(
        field_name=field_name,
        total=total,
        non_null=non_null,
        distinct=len(seen),
        avg_length=avg_length,
        numeric_ratio=numeric / non_null if non_null else 0.0,
        alpha_ratio=alpha / non_null if non_null else 0.0,
        alnum_ratio=alnum / non_null if non_null else 0.0,
        max_length=max(lengths, default=0),
    )

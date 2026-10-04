"""Verdict produced for a single column by the discovery pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

# Reuse the same sensitivity vocabulary as the declared catalog.
KNOWN_SENSITIVITIES = {"public", "personal", "sensitive", "special"}

# An empty/unknown shape: profiler did not see enough non-null values.
SENSITIVITY_UNKNOWN = "unknown"

REVIEW_STATUSES = ("none", "pending")
ORIGINS = ("auto", "manual")


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


@dataclass(frozen=True)
class Verdict:
    """One column's current conclusion.

    ``origin`` distinguishes machine verdicts from human confirmations.
    Confirmed verdicts (``origin == "manual"``) are the source of truth and
    are never overwritten by later scans.
    """

    field_name: str
    sensitivity: str
    confidence: str
    origin: str
    review_status: str
    fingerprint: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    suggested_sensitivity: str = ""
    decided_by: str = ""
    decided_at: str = ""

    def __post_init__(self) -> None:
        if not _is_text(self.field_name):
            raise ValueError("field name is required")
        allowed = KNOWN_SENSITIVITIES | {SENSITIVITY_UNKNOWN}
        if self.sensitivity not in allowed:
            raise ValueError(f"unknown sensitivity {self.sensitivity!r}")
        if self.confidence not in {item.value for item in Confidence}:
            raise ValueError(f"unknown confidence {self.confidence!r}")
        if self.origin not in ORIGINS:
            raise ValueError(f"unknown origin {self.origin!r}")
        if self.review_status not in REVIEW_STATUSES:
            raise ValueError(f"unknown review status {self.review_status!r}")
        if not _is_text(self.fingerprint):
            raise ValueError("fingerprint is required")

    @property
    def needs_review(self) -> bool:
        return self.review_status == "pending"

    @property
    def is_confirmed(self) -> bool:
        return self.origin == "manual"

    @property
    def is_actionable(self) -> bool:
        """A public/non-public conclusion safe to carry into the catalog."""

        return (
            self.sensitivity in KNOWN_SENSITIVITIES
            and not self.needs_review
            and (self.origin == "manual" or self.confidence == Confidence.HIGH.value)
        )

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "Verdict | None":
        if not isinstance(payload, dict):
            return None
        name = payload.get("field_name")
        sensitivity = payload.get("sensitivity")
        confidence = payload.get("confidence")
        origin = payload.get("origin")
        review_status = payload.get("review_status")
        fingerprint = payload.get("fingerprint")
        if not all(isinstance(item, str) for item in (
            name, sensitivity, confidence, origin, review_status, fingerprint
        )):
            return None
        raw_evidence = payload.get("evidence", [])
        if not isinstance(raw_evidence, list) or not all(
            isinstance(item, str) for item in raw_evidence
        ):
            return None
        try:
            return cls(
                field_name=name,
                sensitivity=sensitivity,
                confidence=confidence,
                origin=origin,
                review_status=review_status,
                fingerprint=fingerprint,
                evidence=tuple(raw_evidence),
                suggested_sensitivity=_optional(payload.get("suggested_sensitivity")),
                decided_by=_optional(payload.get("decided_by")),
                decided_at=_optional(payload.get("decided_at")),
            )
        except ValueError:
            return None


def _optional(value: object) -> str:
    return value if isinstance(value, str) else ""

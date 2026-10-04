"""Combine name and sample detector hits into one decision per column."""

from __future__ import annotations

from dataclasses import dataclass, field

from maskhub.discovery.profile import ColumnProfile
from maskhub.discovery.signals import Detector, NameMatch, builtin_detectors
from maskhub.discovery.verdict import SENSITIVITY_UNKNOWN

# Confidence thresholds. The scan is deliberately conservative: anything it
# cannot state confidently lands in the human review queue instead of being
# silently labelled public.
HIGH_AT_LEAST = 0.85
MEDIUM_AT_LEAST = 0.55
# Below this many observed values, shape evidence is too thin to trust alone.
MIN_SAMPLE_SIZE = 3


@dataclass(frozen=True)
class Candidate:
    detector: Detector
    name_match: NameMatch
    ratio: float | None
    score: float
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    sensitivity: str
    confidence: str
    review_required: bool
    suggested_sensitivity: str
    evidence: tuple[str, ...] = field(default_factory=tuple)


def _decision_unknown(evidence: list[str], review_required: bool = True) -> Decision:
    return Decision(
        sensitivity=SENSITIVITY_UNKNOWN,
        confidence="low",
        review_required=review_required,
        suggested_sensitivity="",
        evidence=tuple(evidence),
    )


def classify(
    profile: ColumnProfile,
    values: list[object],
    detectors: tuple[Detector, ...] | None = None,
) -> Decision:
    """Judge one column from its profile plus the raw sample values."""

    if profile.non_null < MIN_SAMPLE_SIZE:
        return _decision_unknown(
            [f"sample too small: {profile.non_null} non-null value(s), human review required"]
        )

    text_values = [item if isinstance(item, str) else str(item) for item in values]
    candidates: list[Candidate] = []
    for detector in detectors or builtin_detectors():
        name_match = detector.name_match(profile.field_name)
        if name_match is NameMatch.NONE and detector.pattern_mode == "any":
            # Shape-only detectors (free text such as names/addresses) cannot
            # say anything without a name signal, so skip them entirely.
            continue
        ratio = detector.sample_ratio(profile, text_values)
        score, evidence = _score(detector, name_match, ratio)
        if score <= 0:
            continue
        candidates.append(Candidate(detector, name_match, ratio, score, tuple(evidence)))

    if not candidates:
        # No sensitivity signal at all: an ordinary column. It is recorded as
        # unrecognised (not silently labelled public) but kept OUT of the
        # review queue, so reviewers only see columns that actually look risky.
        return _decision_unknown(
            ["no name keyword or sample pattern matched; treated as ordinary column"],
            review_required=False,
        )

    candidates.sort(key=lambda item: item.score, reverse=True)
    best = candidates[0]
    evidence = list(best.evidence)

    # Rival candidates pointing at a different sensitivity mean the signals
    # are contradictory: surface both and defer to a human.
    rivals = [
        item for item in candidates[1:]
        if item.score >= MEDIUM_AT_LEAST
        and item.detector.sensitivity != best.detector.sensitivity
    ]
    conflicting = bool(rivals)
    for rival in rivals:
        evidence.append(
            f"conflicting signal: {rival.detector.label} "
            f"({rival.detector.sensitivity}, score {rival.score:.2f})"
        )

    score = best.score
    if conflicting:
        score = min(score, MEDIUM_AT_LEAST - 0.01)

    if score >= HIGH_AT_LEAST:
        confidence = "high"
        review_required = False
    elif score >= MEDIUM_AT_LEAST:
        confidence = "medium"
        review_required = True
    else:
        confidence = "low"
        review_required = True

    suggested = ""
    sensitivity = best.detector.sensitivity
    if review_required:
        # Keep the column unlabelled until a human settles it.
        suggested = sensitivity
        sensitivity = SENSITIVITY_UNKNOWN

    return Decision(
        sensitivity=sensitivity,
        confidence=confidence,
        review_required=review_required,
        suggested_sensitivity=suggested,
        evidence=tuple(evidence),
    )


def _score(
    detector: Detector,
    name_match: NameMatch,
    ratio: float | None,
) -> tuple[float, list[str]]:
    evidence: list[str] = []

    # Name signal on its own is suggestive but not conclusive.
    if name_match is NameMatch.STRONG:
        evidence.append(f"column name matches {detector.label} keyword")

    if ratio is not None and ratio < detector.min_ratio:
        # Weak/partial sample evidence: useful only as corroboration.
        if name_match is NameMatch.STRONG and ratio > 0:
            evidence.append(f"{ratio:.0%} of samples look like {detector.label} (partial)")
            return 0.4, evidence
        return 0.0, evidence

    if name_match is NameMatch.STRONG and ratio is not None:
        evidence.append(
            f"{ratio:.0%} of non-null samples match {detector.label} shape"
        )
        # Double agreement: very high confidence.
        return 0.95, evidence

    if name_match is NameMatch.STRONG:
        # Name-only detectors (free-form text): name is all there is.
        evidence.append("classified from column name only; no shape pattern available")
        return 0.7, evidence

    if ratio is not None:
        evidence.append(
            f"{ratio:.0%} of non-null samples match {detector.label} shape "
            "(no column-name signal)"
        )
        # Pure shape hit: strong formats (checksummed identifiers) can still
        # be conclusive; a name-less regex match alone stays in review.
        if detector.checksum and ratio >= 0.95:
            return 0.9, evidence
        return round(0.5 + 0.3 * ratio, 2), evidence

    return 0.0, evidence

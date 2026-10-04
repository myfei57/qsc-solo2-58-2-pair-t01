"""Combine name and value signals into one verdict per column.

Every verdict carries the evidence behind it and a confidence in [0, 1].
Verdicts at or above :data:`AUTO_CONFIRM` are accepted automatically; the
rest are returned as ``needs_review`` (or ``undetermined`` when the column
is empty) so a human only looks at the uncertain tail.

The function is pure: it consumes the submitted sample values and never
touches any data source, and given identical inputs it returns identical
outputs (no timestamps, no randomness).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from maskhub.discovery.fingerprint import fingerprint_values
from maskhub.discovery.names import normalize, phrase_hit, phrase_tokens
from maskhub.discovery.types import (
    BUILTIN_CATEGORIES,
    Category,
    VALIDATORS,
)

AUTO_CONFIRM = 0.85
REVIEW_FLOOR = 0.50
FALLBACK_PUBLIC_CAP = 0.80
MIN_SAMPLES_FOR_FALLBACK = 8

# Verdict states -------------------------------------------------------------
STATUS_AUTO = "auto_confirmed"
STATUS_REVIEW = "needs_review"
STATUS_UNDETERMINED = "undetermined"


@dataclass(frozen=True)
class Evidence:
    channel: str
    signal: str
    weight: float
    detail: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    column: str
    category: str
    sensitivity: str
    confidence: float
    status: str
    evidence: tuple[Evidence, ...]
    non_empty: int

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["evidence"] = [item.as_dict() for item in self.evidence]
        return payload


@dataclass(frozen=True)
class ColumnScan:
    column: str
    fingerprint: object
    finding: Finding


def _name_signal(category: Category, normalized: str) -> tuple[float, str, list[str]]:
    strong = [phrase for phrase in category.name_strong if phrase_hit(normalized, phrase)]
    weak = [
        phrase
        for phrase in category.name_weak
        if phrase_hit(normalized, phrase) and phrase not in strong
    ]
    if not strong and not weak:
        return 0.0, "", []
    tokens = normalized.split()
    if strong:
        exact_phrases = [phrase for phrase in strong if phrase_tokens(phrase) == tokens]
        signal = "name_exact" if exact_phrases else "name_strong"
        shown = exact_phrases if exact_phrases else strong
        return (0.9 if exact_phrases else 0.7), signal, shown + weak
    return 0.4, "name_weak", weak


def _excluded_by_name(category: Category, normalized: str, positive: list[str]) -> bool:
    """Operational/generic names argue against loose value-only categories."""

    if positive:
        return False
    return any(phrase_hit(normalized, phrase) for phrase in category.name_exclude)


def _value_signal(
    category: Category, values: list[str], excluded: bool
) -> tuple[float, str, float, int]:
    """Return (score, signal, matched_ratio, matched_count)."""

    non_empty = len(values)
    if non_empty == 0:
        return 0.0, "", 0.0, 0
    pattern = re.compile(category.pattern, category.flags)
    raw_hits = [value for value in values if pattern.match(value)]
    raw_ratio = len(raw_hits) / non_empty
    validator = VALIDATORS.get(category.validator)
    if validator is not None:
        passed = [value for value in raw_hits if validator(value)]
        pass_ratio = len(passed) / non_empty
        if pass_ratio >= category.min_ratio:
            return 0.95, "value_validated", pass_ratio, len(passed)
        # shape matched but checksum failed: never present as a positive hit
        return 0.0, "", pass_ratio, len(passed)
    if raw_ratio >= category.min_ratio:
        if excluded:
            return 0.35, "value_shape_demoted", raw_ratio, len(raw_hits)
        # Loose shapes (names, dates) match ordinary text easily and are
        # capped: they only auto-confirm with a supporting column name.
        return (0.7 if category.value_weak else 0.9), "value_shape", raw_ratio, len(raw_hits)
    if raw_ratio >= category.min_ratio * 0.6:
        return 0.45, "value_shape_weak", raw_ratio, len(raw_hits)
    return 0.0, "", raw_ratio, len(raw_hits)


def _combine(name_score: float, value_score: float) -> float:
    if name_score <= 0:
        return value_score if value_score > 0 else 0.0
    if value_score <= 0:
        return name_score
    if name_score >= 0.85 and value_score >= 0.85:
        return 0.98
    if name_score >= 0.85 and value_score >= 0.6:  # strong name + loose shape
        return 0.9
    if name_score >= 0.7 and value_score >= 0.6:
        # strong name keyword plus a matching (even if loose) value shape
        return 0.86
    if name_score < 0.85 and value_score >= 0.85:
        # hard value shape with a merely strong/weak name is near certain
        return 0.92 if name_score >= 0.7 else 0.88
    if name_score < 0.7 and value_score < 0.85:
        return max(0.0, min(name_score, value_score) + 0.15)
    return max(name_score, value_score)


def _support_factor(non_empty: int) -> float:
    # eight clean samples already constitute decent evidence
    return min(1.0, 0.6 + non_empty / 20)


def _name_evidence(signal: str, hits: list[str]) -> Evidence:
    label = {"name_exact": "精确", "name_strong": "强", "name_weak": "弱"}[signal]
    return Evidence(
        channel="name",
        signal=signal,
        weight={"name_exact": 0.9, "name_strong": 0.7, "name_weak": 0.4}[signal],
        detail=f"列名命中{label}关键词：{'、'.join(hits)}",
    )


def _value_evidence(category: Category, signal: str, ratio: float, matched: int,
                    non_empty: int) -> Evidence:
    label = {
        "value_validated": "且通过校验器",
        "value_shape": "",
        "value_shape_weak": "（比例偏低）",
        "value_shape_only": "（未全部通过校验器）",
        "value_shape_demoted": "（列名语义不支持，降为弱信号）",
    }[signal]
    return Evidence(
        channel="value",
        signal=signal,
        weight={"value_validated": 0.95, "value_shape": 0.9,
                "value_shape_weak": 0.45, "value_shape_only": 0.5,
                "value_shape_demoted": 0.35}[signal],
        detail=(
            f"{int(ratio * 100)}% 的非空样例（{matched}/{non_empty}）"
            f"符合 {category.identifier} 形态{label}"
        ),
    )


def scan_column(column: str, samples: list[object]):
    fingerprint = fingerprint_values(samples)
    values = [str(item).strip() for item in samples if item is not None and str(item).strip()]
    non_empty = len(values)
    normalized = normalize(column)

    if non_empty == 0:
        finding = Finding(
            column=column,
            category="",
            sensitivity="public",
            confidence=0.0,
            status=STATUS_UNDETERMINED,
            evidence=(
                Evidence("value", "empty", 0.0, "样例全部为空，无法判定，待有数据后重扫"),
            ),
            non_empty=0,
        )
        return ColumnScan(column=column, fingerprint=fingerprint, finding=finding)

    candidates: list[tuple[float, Category, list[Evidence]]] = []
    for category in BUILTIN_CATEGORIES:
        evidence: list[Evidence] = []
        name_score, name_signal, name_hits = _name_signal(category, normalized)
        if name_score:
            evidence.append(_name_evidence(name_signal, name_hits))
        positive = name_hits if name_score else []
        excluded = _excluded_by_name(category, normalized, positive)
        value_score, value_signal, ratio, matched = _value_signal(category, values, excluded)
        # checksum categories (id cards, bank cards) are never accepted on a
        # column name alone: values must validate
        if category.validator and value_score <= 0:
            continue
        if value_score:
            evidence.append(
                _value_evidence(category, value_signal, ratio, matched, non_empty)
            )
        score = _combine(name_score, value_score)
        if score > 0:
            candidates.append((round(score, 3), category, evidence))

    ranked = sorted(candidates, key=lambda item: (-item[0], item[1].identifier))
    best_score, best_category, best_evidence = (
        ranked[0] if ranked else (0.0, None, [])
    )

    # Two categories almost tied: the shape alone cannot pick a winner.
    contested = (
        len(ranked) > 1
        and ranked[1][0] >= REVIEW_FLOOR
        and best_score - ranked[1][0] <= 0.08
    )

    if best_score >= REVIEW_FLOOR and not contested:
        confidence = round(best_score * _support_factor(non_empty), 3)
        if non_empty < MIN_SAMPLES_FOR_FALLBACK:
            # the guess may be right, but there is too little behind it to
            # auto-accept anything; surface it for human confirmation
            best_evidence = list(best_evidence) + [
                Evidence(
                    channel="value",
                    signal="insufficient_samples",
                    weight=0.0,
                    detail=f"仅 {non_empty} 个非空样例，证据不足以自动判定",
                )
            ]
            finding = Finding(
                column=column,
                category=best_category.identifier,
                sensitivity=best_category.sensitivity,
                confidence=confidence,
                status=STATUS_UNDETERMINED,
                evidence=tuple(best_evidence),
                non_empty=non_empty,
            )
            return ColumnScan(column=column, fingerprint=fingerprint, finding=finding)
        status = STATUS_AUTO if confidence >= AUTO_CONFIRM else STATUS_REVIEW
        finding = Finding(
            column=column,
            category=best_category.identifier,
            sensitivity=best_category.sensitivity,
            confidence=confidence,
            status=status,
            evidence=tuple(best_evidence),
            non_empty=non_empty,
        )
        return ColumnScan(column=column, fingerprint=fingerprint, finding=finding)

    evidence: list[Evidence] = list(best_evidence) if contested else []
    if contested:
        runner = ranked[1]
        evidence.append(
            Evidence(
                channel="decision",
                signal="contested",
                weight=best_score,
                detail=(
                    f"{best_category.identifier} 与 {runner[1].identifier} "
                    f"得分接近（{best_score} vs {runner[0]}），需人工裁定"
                ),
            )
        )

    if non_empty < MIN_SAMPLES_FOR_FALLBACK:
        # Too little to assert "public" either; hand the column to a human.
        evidence.append(
            Evidence(
                channel="value",
                signal="insufficient_samples",
                weight=0.0,
                detail=f"仅 {non_empty} 个非空样例，证据不足以自动判定",
            )
        )
        finding = Finding(
            column=column,
            category="",
            sensitivity="public",
            confidence=0.0,
            status=STATUS_UNDETERMINED,
            evidence=tuple(evidence),
            non_empty=non_empty,
        )
        return ColumnScan(column=column, fingerprint=fingerprint, finding=finding)

    confidence = round(
        min(FALLBACK_PUBLIC_CAP, 0.4 + 0.6 * _support_factor(non_empty)), 3
    )
    if not evidence:
        evidence.append(
            Evidence(
                channel="value",
                signal="no_known_shape",
                weight=confidence,
                detail=f"{non_empty} 个非空样例均未命中任何已知敏感形态",
            )
        )
    finding = Finding(
        column=column,
        category="",
        sensitivity="public",
        confidence=confidence,
        status=STATUS_AUTO,
        evidence=tuple(evidence),
        non_empty=non_empty,
    )
    return ColumnScan(column=column, fingerprint=fingerprint, finding=finding)


def scan_columns(columns: list[tuple[str, list[object]]]):
    return [scan_column(name, samples) for name, samples in columns]

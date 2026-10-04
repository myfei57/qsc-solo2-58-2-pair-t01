"""Persistent per-dataset verdict registry.

One document per dataset holds every column verdict. The reconciliation rules
applied on every scan are:

* human-confirmed verdicts are immutable to the scanner;
* unchanged shape fingerprints keep their previous auto verdict untouched, so
  conclusions stay stable between runs;
* a changed fingerprint is the only thing that re-opens an auto verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone

from maskhub.discovery.verdict import SENSITIVITY_UNKNOWN, Verdict
from maskhub.errors import Conflict, InvalidRequest, NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "discovery."

KNOWN_SENSITIVITIES = {"public", "personal", "sensitive", "special"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def discovery_key(dataset: str) -> str:
    return PREFIX + dataset


class VerdictRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    # ------------------------------------------------------------------ I/O

    def _load(self, dataset: str) -> dict[str, Verdict]:
        document = self._store.get_json(discovery_key(dataset))
        if not isinstance(document, list):
            return {}
        verdicts: dict[str, Verdict] = {}
        for raw in document:
            verdict = Verdict.from_dict(raw)
            if verdict is not None:
                verdicts[verdict.field_name] = verdict
        return verdicts

    def _save(self, dataset: str, verdicts: dict[str, Verdict]) -> None:
        ordered = [verdicts[name].as_dict() for name in sorted(verdicts)]
        self._store.put_json(discovery_key(dataset), ordered)

    def get(self, dataset: str, field_name: str) -> Verdict:
        verdict = self._load(dataset).get(field_name)
        if verdict is None:
            raise NotFound(f"no verdict for {dataset}.{field_name}")
        return verdict

    def for_dataset(self, dataset: str) -> list[Verdict]:
        return list(self._load(dataset).values())

    def datasets(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]

    def review_queue(self, dataset: str | None = None) -> list[dict[str, str]]:
        names = [dataset] if dataset else self.datasets()
        queued: list[dict[str, str]] = []
        for name in names:
            for verdict in self._load(name).values():
                if verdict.needs_review:
                    item = verdict.as_dict()
                    item["dataset"] = name
                    queued.append(item)  # type: ignore[arg-type]
        return queued

    # ----------------------------------------------------------- scanning

    def apply_scan(
        self,
        dataset: str,
        observations: list[tuple[str, str, object]],
    ) -> dict[str, object]:
        """Reconcile a fresh scan against stored verdicts.

        Each observation is ``(field_name, fingerprint, Decision)``.
        """

        verdicts = self._load(dataset)
        seen: set[str] = set()
        reused = reopened = confirmed_kept = pending = 0
        confirmed_drift: list[str] = []

        for field_name, fingerprint, decision in observations:
            seen.add(field_name)
            previous = verdicts.get(field_name)

            if previous is not None and previous.is_confirmed:
                # Human truth wins; scanning can never overwrite it.
                confirmed_kept += 1
                if previous.fingerprint != fingerprint:
                    # The data shape changed under a confirmed conclusion.
                    # Keep the confirmation but flag it so reviewers can check
                    # whether the column's meaning (not just rows) changed.
                    confirmed_drift.append(field_name)
                if previous.needs_review:
                    pending += 1
                continue

            if (
                previous is not None
                and not previous.is_confirmed
                and previous.fingerprint == fingerprint
            ):
                # Same shape: the prior conclusion stays exactly as it was.
                if previous.needs_review:
                    pending += 1
                reused += 1
                continue

            # New column, or an auto verdict whose shape genuinely changed.
            if previous is not None:
                reopened += 1
            review_status = "pending" if decision.review_required else "none"
            if review_status == "pending":
                pending += 1
            verdicts[field_name] = Verdict(
                field_name=field_name,
                sensitivity=decision.sensitivity,
                confidence=decision.confidence,
                origin="auto",
                review_status=review_status,
                fingerprint=fingerprint,
                evidence=decision.evidence,
                suggested_sensitivity=decision.suggested_sensitivity,
            )

        # Columns that disappeared from the scan keep their verdict: deleting
        # a data protection conclusion must never be an implicit side effect.
        missing = sorted(set(verdicts) - seen)

        self._save(dataset, verdicts)
        return {
            "dataset": dataset,
            "scanned": len(seen),
            "reused": reused,
            "reopened": reopened,
            "confirmed_preserved": confirmed_kept,
            "confirmed_drift": confirmed_drift,
            "missing": missing,
            "pending_review": pending,
        }

    # ------------------------------------------------------------- review

    def confirm(
        self,
        dataset: str,
        field_name: str,
        sensitivity: str,
        reviewer: str,
    ) -> Verdict:
        if sensitivity not in KNOWN_SENSITIVITIES:
            raise InvalidRequest(f"unknown sensitivity {sensitivity!r}")
        verdicts = self._load(dataset)
        previous = verdicts.get(field_name)
        if previous is None:
            raise NotFound(f"no verdict for {dataset}.{field_name}")
        if previous.is_confirmed and previous.sensitivity == sensitivity:
            raise Conflict(f"{dataset}.{field_name} already confirmed as {sensitivity}")

        verdict = Verdict(
            field_name=field_name,
            sensitivity=sensitivity,
            confidence="high",
            origin="manual",
            review_status="none",
            fingerprint=previous.fingerprint,
            evidence=(
                f"human reviewer {reviewer!r} confirmed {sensitivity}",
                *previous.evidence,
            ),
            suggested_sensitivity="",
            decided_by=reviewer,
            decided_at=_now(),
        )
        verdicts[field_name] = verdict
        self._save(dataset, verdicts)
        return verdict

    def release_to_review(self, dataset: str, field_name: str, reviewer: str) -> Verdict:
        """Undo a confirmation so a column goes back into the review queue."""

        verdicts = self._load(dataset)
        previous = verdicts.get(field_name)
        if previous is None:
            raise NotFound(f"no verdict for {dataset}.{field_name}")
        if not previous.is_confirmed:
            raise Conflict(f"{dataset}.{field_name} is not human confirmed")
        verdict = Verdict(
            field_name=field_name,
            sensitivity=SENSITIVITY_UNKNOWN,
            confidence="low",
            origin="auto",
            review_status="pending",
            fingerprint=previous.fingerprint,
            evidence=(f"confirmation released by {reviewer!r}", *previous.evidence),
            suggested_sensitivity=previous.sensitivity,
            decided_by=reviewer,
            decided_at=_now(),
        )
        verdicts[field_name] = verdict
        self._save(dataset, verdicts)
        return verdict

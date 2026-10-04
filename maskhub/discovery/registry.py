"""Per-dataset discovery archive and cross-scan reconciliation.

One store document per dataset holds the verdict of every column ever seen.
Reconciliation rules on a new scan:

* ``confirmed`` / ``rejected`` verdicts are *locked*. Re-scanning never
  overwrites them; when the fresh fingerprint differs from the baseline the
  verdict is merely flagged ``drift`` so a human can re-check.
* machine verdicts are reused unchanged while their shape signature and the
  ruleset version are unchanged (stable conclusions across scans);
* a changed signature or a newer ruleset version triggers re-evaluation;
* columns missing from a scan are kept and marked ``absent`` — nothing is
  deleted or rewritten without an explicit human decision.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from maskhub.discovery.fingerprint import ColumnFingerprint
from maskhub.discovery.scanner import (
    ColumnScan,
    scan_columns,
)
from maskhub.discovery.types import ruleset_version
from maskhub.errors import Conflict, NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "discovery."

# Provenance / status ---------------------------------------------------------
ORIGIN_AUTO = "auto"
ORIGIN_MANUAL = "manual"

STATE_CONFIRMED = "confirmed"
STATE_REJECTED = "rejected"
STATE_MACHINE = "machine"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def discovery_key(dataset: str) -> str:
    return PREFIX + dataset


class ColumnRecord:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.data = payload

    @classmethod
    def from_scan(
        cls, dataset: str, scan: ColumnScan, rule_version: str, at: str
    ) -> "ColumnRecord":
        finding = scan.finding
        signature = scan.fingerprint.signature()
        return cls(
            {
                "dataset": dataset,
                "column": scan.column,
                "category": finding.category,
                "sensitivity": finding.sensitivity,
                "confidence": finding.confidence,
                "status": finding.status,
                "origin": ORIGIN_AUTO,
                "evidence": [item.as_dict() for item in finding.evidence],
                "fingerprint": scan.fingerprint.as_dict(),
                "shape_signature": signature,
                "baseline_signature": signature,
                "rule_version": rule_version,
                "drift": False,
                "present_last_scan": True,
                "decided_by": "",
                "decided_at": "",
                "note": "",
                "last_seen": at,
            }
        )

    @property
    def column(self) -> str:
        return str(self.data["column"])

    @property
    def locked(self) -> bool:
        return self.data.get("origin") == ORIGIN_MANUAL

    def as_dict(self) -> dict[str, Any]:
        return dict(self.data)


class DiscoveryArchive:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    def scan(
        self,
        dataset: str,
        columns: list[tuple[str, list[object]]],
        rule_version: str | None = None,
    ) -> dict[str, Any]:
        version = rule_version or ruleset_version()
        at = _now()
        fresh = {item.column: item for item in scan_columns(columns)}
        document = self._load(dataset)
        existing = {item["column"]: item for item in document["columns"]}

        reused: list[str] = []
        reevaluated: list[str] = []
        drifted: list[str] = []
        locked_kept: list[str] = []

        for name, record in existing.items():
            record["present_last_scan"] = False

        for column in sorted(fresh):
            scan = fresh[column]
            signature = scan.fingerprint.signature()
            previous = existing.get(column)
            if previous is None:
                existing[column] = ColumnRecord.from_scan(dataset, scan, version, at).data
                reevaluated.append(column)
                continue

            shape_changed = previous.get("shape_signature") != signature
            rules_changed = previous.get("rule_version") != version

            if previous.get("origin") == ORIGIN_MANUAL:
                # Human verdict wins over every scan; only annotate drift.
                baseline = previous.get("baseline_signature") or previous.get(
                    "shape_signature"
                )
                drift = baseline != signature
                previous["drift"] = drift
                previous["fingerprint"] = scan.fingerprint.as_dict()
                previous["shape_signature"] = signature
                previous["present_last_scan"] = True
                previous["last_seen"] = at
                locked_kept.append(column)
                if drift:
                    drifted.append(column)
                continue

            if not shape_changed and not rules_changed:
                # Same data shape, same rule catalog: verdict stays put.
                previous["present_last_scan"] = True
                previous["last_seen"] = at
                reused.append(column)
                continue

            replacement = ColumnRecord.from_scan(dataset, scan, version, at).data
            replacement["baseline_signature"] = previous.get(
                "baseline_signature", signature
            )
            replacement["drift"] = replacement["baseline_signature"] != signature
            existing[column] = replacement
            reevaluated.append(column)
            if replacement["drift"]:
                drifted.append(column)

        absent = sorted(
            name for name, record in existing.items() if not record["present_last_scan"]
        )

        document["columns"] = [existing[name] for name in sorted(existing)]
        document["rule_version"] = version
        document["last_scan_at"] = at
        self._store.put_json(discovery_key(dataset), document)

        present = [existing[name] for name in sorted(fresh)]
        return {
            "dataset": dataset,
            "scanned_at": at,
            "rule_version": version,
            "columns_scanned": len(fresh),
            "verdicts_reused": reused,
            "verdicts_reevaluated": reevaluated,
            "manual_verdicts_kept": locked_kept,
            "shape_drift": drifted,
            "absent_columns": absent,
            "auto_confirmed": [
                r["column"]
                for r in present
                if r["status"] == "auto_confirmed"
                and r.get("origin") != ORIGIN_MANUAL
            ],
            "needs_review": [r["column"] for r in present if r["status"] == "needs_review"],
            "undetermined": sorted(
                r["column"]
                for r in present
                if r["status"] == "undetermined" and r.get("origin") != ORIGIN_MANUAL
            ),
            "manual_locked": [
                r["column"]
                for r in present
                if r.get("origin") == ORIGIN_MANUAL
            ],
            "columns": [existing[name] for name in sorted(existing)],
        }

    # ------------------------------------------------------------------
    def get(self, dataset: str) -> dict[str, Any]:
        document = self._load(dataset)
        if not document["columns"]:
            raise NotFound(f"no discovery scan for dataset {dataset}")
        return document

    def review_queue(self) -> list[dict[str, Any]]:
        queue: list[dict[str, Any]] = []
        for dataset in self.identifiers():
            document = self._load(dataset)
            for record in document["columns"]:
                reasons = []
                if record["status"] in {"needs_review", "undetermined"}:
                    reasons.append(record["status"])
                if record.get("drift"):
                    if record.get("origin") == ORIGIN_MANUAL:
                        reasons.append("manual_verdict_shape_drift")
                    elif record.get("origin") == ORIGIN_AUTO:
                        reasons.append("auto_verdict_shape_drift")
                if reasons:
                    entry = dict(record)
                    entry["review_reasons"] = reasons
                    queue.append(entry)
        return sorted(queue, key=lambda item: (item["dataset"], item["column"]))

    def decide(
        self,
        dataset: str,
        column: str,
        decision: str,
        reviewer: str,
        sensitivity: str | None = None,
        category: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        from maskhub.discovery.types import SENSITIVITY_LEVELS, categories_by_id

        document = self._load(dataset)
        target = next((item for item in document["columns"] if item["column"] == column), None)
        if target is None:
            raise NotFound(f"column {column!r} was never scanned in dataset {dataset}")
        if decision not in {STATE_CONFIRMED, STATE_REJECTED}:
            raise Conflict(f"unknown decision {decision!r}")
        if decision == STATE_CONFIRMED:
            if sensitivity is not None and sensitivity not in SENSITIVITY_LEVELS:
                raise Conflict(f"unknown sensitivity {sensitivity!r}")
            if category is not None and category not in categories_by_id():
                raise Conflict(f"unknown category {category!r}")

        target["origin"] = ORIGIN_MANUAL
        target["status"] = decision
        target["decided_by"] = reviewer
        target["decided_at"] = _now()
        target["note"] = note
        target["drift"] = False
        if decision == STATE_CONFIRMED:
            if sensitivity is not None:
                target["sensitivity"] = sensitivity
            if category is not None:
                target["category"] = category
            target["baseline_signature"] = target["shape_signature"]
        else:
            # A rejected guess means "reviewed and judged not sensitive here".
            target["sensitivity"] = "public"
        self._store.put_json(discovery_key(dataset), document)
        return target

    def identifiers(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]

    # ------------------------------------------------------------------
    def _load(self, dataset: str) -> dict[str, Any]:
        raw = self._store.get_json(discovery_key(dataset))
        if not isinstance(raw, dict) or not isinstance(raw.get("columns"), list):
            return {"dataset": dataset, "columns": [], "rule_version": "", "last_scan_at": ""}
        return raw

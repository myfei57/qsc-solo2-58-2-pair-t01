"""Scan orchestration: profile -> classify -> reconcile, read-only on data."""

from __future__ import annotations

from maskhub.catalog.dataset import Dataset
from maskhub.catalog.field import Field
from maskhub.discovery.classifier import classify
from maskhub.discovery.profile import profile_column
from maskhub.discovery.registry import VerdictRegistry
from maskhub.errors import InvalidRequest, NotFound


class DiscoveryScanner:
    def __init__(self, registry: VerdictRegistry) -> None:
        self._registry = registry

    def scan(self, dataset: str, columns: list[dict[str, object]]) -> dict[str, object]:
        if not isinstance(columns, list) or not columns:
            raise InvalidRequest("columns must be a non-empty list")

        observations: list[tuple[str, str, object]] = []
        for column in columns:
            if not isinstance(column, dict):
                raise InvalidRequest("each column must be an object")
            name = column.get("name")
            if not isinstance(name, str) or not name.strip():
                raise InvalidRequest("column.name is required")
            samples = column.get("samples", [])
            if not isinstance(samples, list):
                raise InvalidRequest(f"column {name!r} samples must be a list")
            profile = profile_column(name, samples)
            decision = classify(profile, samples)
            observations.append((name, profile.fingerprint(), decision))

        return self._registry.apply_scan(dataset, observations)

    def promote(
        self,
        dataset: str,
        declared_by: str = "discovery",
        datasets: object = None,
    ) -> dict[str, object]:
        """Write actionable verdicts into the declared field catalog.

        Only verified/high-confidence conclusions are promoted; review-pending
        and ``unknown`` columns are skipped. Existing catalog fields (manual or
        previously promoted) are never overwritten.
        """

        if datasets is None:
            raise InvalidRequest("dataset registry is required")
        existing = datasets.find(dataset)
        if existing is None:
            raise NotFound(f"unknown dataset {dataset}")

        catalog: dict[str, Field] = {item.name: item for item in existing.fields}
        promoted: list[str] = []
        skipped: list[dict[str, str]] = []

        for verdict in self._registry.for_dataset(dataset):
            current = catalog.get(verdict.field_name)
            if current is not None:
                skipped.append(
                    {"field": verdict.field_name, "reason": "catalog field already declared"}
                )
                continue
            if not verdict.is_actionable:
                skipped.append(
                    {"field": verdict.field_name, "reason": "verdict not confirmed/high-confidence"}
                )
                continue
            catalog[verdict.field_name] = Field(
                name=verdict.field_name,
                sensitivity=verdict.sensitivity,
                declared_by=declared_by,
            )
            promoted.append(verdict.field_name)

        if promoted:
            updated = Dataset(
                identifier=existing.identifier,
                source=existing.source,
                owner=existing.owner,
                fields=tuple(catalog[name] for name in sorted(catalog)),
            )
            datasets.save(updated)

        return {
            "dataset": dataset,
            "promoted": promoted,
            "skipped": skipped,
        }

"""Publish reviewed/accepted discovery verdicts into the field catalog.

Publishing is deliberately conservative: fields declared by a human in the
catalog are never touched, duplicated or removed. Discovery only manages
fields tagged ``declared_by="discovery:<state>"``. Column names that a human
already owns are skipped entirely on publish (and reported back), so a
re-publish can propagate newly accepted columns but can never overwrite a
human-confirmed conclusion.
"""

from __future__ import annotations

from maskhub.catalog.dataset import Dataset, DatasetRegistry
from maskhub.catalog.field import Field
from maskhub.discovery.registry import STATE_CONFIRMED, STATE_REJECTED, DiscoveryArchive

DISCOVERY_PREFIX = "discovery:"
MANAGED_STATES = {"auto_confirmed", STATE_CONFIRMED}


def publish_to_catalog(
    archive: DiscoveryArchive,
    datasets: DatasetRegistry,
    dataset_id: str,
    owner: str = "",
    include_auto: bool = True,
) -> dict[str, object]:
    document = archive.get(dataset_id)
    dataset = datasets.get(dataset_id)

    human_fields = [f for f in dataset.fields if not f.declared_by.startswith(DISCOVERY_PREFIX)]
    human_names = {field.name for field in human_fields}

    records = {record["column"]: record for record in document["columns"]}

    managed: list[Field] = []
    published: list[str] = []
    rejected: list[str] = []
    protected: list[str] = []

    # 1. refresh discovery-managed fields that still have a usable verdict
    for field in dataset.fields:
        if not field.declared_by.startswith(DISCOVERY_PREFIX):
            continue
        record = records.get(field.name)
        if record is None or record["status"] not in (
            MANAGED_STATES | {STATE_REJECTED}
        ):
            continue  # verdict withdrew or went back to review: drop managed copy
        managed.append(
            Field(
                name=field.name,
                sensitivity=record["sensitivity"],
                declared_by=DISCOVERY_PREFIX + record["status"],
            )
        )

    managed_names = {field.name for field in managed}

    # 2. newly publish accepted / rejected verdicts, never over human fields
    for name, record in records.items():
        if name in human_names:
            protected.append(name)
            continue
        if name in managed_names:
            if record["status"] == STATE_REJECTED:
                rejected.append(name)
            else:
                published.append(name)
            continue
        if record["status"] in MANAGED_STATES and (
            include_auto or record["status"] == STATE_CONFIRMED
        ):
            managed.append(
                Field(
                    name=name,
                    sensitivity=record["sensitivity"],
                    declared_by=DISCOVERY_PREFIX + record["status"],
                )
            )
            published.append(name)
        elif record["status"] == STATE_REJECTED:
            managed.append(
                Field(name=name, sensitivity="public",
                      declared_by=DISCOVERY_PREFIX + STATE_REJECTED)
            )
            rejected.append(name)

    final_fields = tuple(sorted(human_fields + managed, key=lambda f: f.name))
    datasets.save(
        Dataset(
            identifier=dataset.identifier,
            source=dataset.source,
            owner=dataset.owner,
            fields=final_fields,
        )
    )
    return {
        "dataset": dataset_id,
        "published": sorted(published),
        "rejected": sorted(rejected),
        "human_fields_protected": sorted(protected),
        "total_fields": len(final_fields),
    }

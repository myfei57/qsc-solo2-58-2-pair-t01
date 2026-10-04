"""Sensitive-column discovery endpoints."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text, require_text
from maskhub.discovery.publishing import publish_to_catalog
from maskhub.discovery.types import BUILTIN_CATEGORIES, ruleset_version
from maskhub.errors import InvalidRequest


def _parse_columns(payload: object) -> list[tuple[str, list[object]]]:
    if not isinstance(payload, list) or not payload:
        raise InvalidRequest("columns must be a non-empty list")
    columns: list[tuple[str, list[object]]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise InvalidRequest("each column must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise InvalidRequest("column name is required")
        samples = item.get("samples", [])
        if samples is None:
            samples = []
        if not isinstance(samples, list):
            raise InvalidRequest(f"column {name!r} samples must be a list")
        columns.append((name.strip(), samples))
    return columns


def scan(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    columns = _parse_columns(payload.get("columns"))
    report = runtime.discovery.scan(dataset, columns)
    runtime.journal.append(
        "discovery.scan",
        dataset,
        (
            f"scanned={report['columns_scanned']} "
            f"auto={len(report['auto_confirmed'])} "
            f"review={len(report['needs_review'])} "
            f"drift={len(report['shape_drift'])}"
        ),
    )
    return Response.json(200, report)


def discovery_status(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset", "") or ""
    return Response.json(200, runtime.discovery.get(dataset))


def review_queue(runtime, request: Request) -> Response:
    queue = runtime.discovery.review_queue()
    return Response.json(200, {"count": len(queue), "columns": queue})


def decide(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    column = require_text(payload, "column")
    decision = require_text(payload, "decision")
    reviewer = require_text(payload, "reviewer")
    sensitivity = payload.get("sensitivity")
    if sensitivity is not None and not isinstance(sensitivity, str):
        raise InvalidRequest("sensitivity must be a string")
    category = payload.get("category")
    if category is not None and not isinstance(category, str):
        raise InvalidRequest("category must be a string")
    note = optional_text(payload, "note")
    record = runtime.discovery.decide(
        dataset,
        column,
        decision,
        reviewer,
        sensitivity=sensitivity,
        category=category,
        note=note,
    )
    runtime.journal.append(f"discovery.{decision}", f"{dataset}:{column}", reviewer)
    return Response.json(200, record)


def publish(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    owner = require_text(payload, "owner")
    include_auto = payload.get("include_auto", True)
    if not isinstance(include_auto, bool):
        raise InvalidRequest("include_auto must be a boolean")
    result = publish_to_catalog(
        runtime.discovery, runtime.datasets, dataset, owner, include_auto=include_auto
    )
    runtime.journal.append(
        "discovery.publish",
        dataset,
        f"published={len(result['published'])} protected={len(result['human_fields_protected'])}",
    )
    return Response.json(200, result)


def categories(runtime, request: Request) -> Response:
    return Response.json(
        200,
        {
            "rule_version": ruleset_version(),
            "count": len(BUILTIN_CATEGORIES),
            "categories": [item.as_dict() for item in BUILTIN_CATEGORIES],
        },
    )

"""Sensitive-column discovery endpoints."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text, require_text
from maskhub.errors import InvalidRequest


def scan_columns(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    columns = payload.get("columns")
    report = runtime.scanner.scan(dataset, columns)
    runtime.journal.append("discovery.scan", dataset, str(report["pending_review"]))
    return Response.json(200, report)


def list_verdicts(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset", "") or ""
    verdicts = [item.as_dict() for item in runtime.discovery.for_dataset(dataset)]
    return Response.json(200, {"dataset": dataset, "count": len(verdicts), "verdicts": verdicts})


def review_queue(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset") or None
    items = runtime.discovery.review_queue(dataset)
    return Response.json(200, {"count": len(items), "pending": items})


def confirm_verdict(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    field_name = require_text(payload, "field")
    sensitivity = require_text(payload, "sensitivity")
    reviewer = optional_text(payload, "reviewer", "anonymous")
    verdict = runtime.discovery.confirm(dataset, field_name, sensitivity, reviewer)
    runtime.journal.append(
        "discovery.confirm",
        f"{dataset}.{field_name}",
        f"{sensitivity} by {reviewer}",
    )
    return Response.json(200, verdict.as_dict())


def release_verdict(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    field_name = require_text(payload, "field")
    reviewer = optional_text(payload, "reviewer", "anonymous")
    verdict = runtime.discovery.release_to_review(dataset, field_name, reviewer)
    runtime.journal.append("discovery.release", f"{dataset}.{field_name}", reviewer)
    return Response.json(200, verdict.as_dict())


def promote_verdicts(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    declared_by = optional_text(payload, "declared_by", "discovery")
    result = runtime.scanner.promote(dataset, declared_by, runtime.datasets)
    runtime.journal.append(
        "discovery.promote",
        dataset,
        f"{len(result['promoted'])} promoted",
    )
    return Response.json(200, result)


def get_verdict(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset", "") or ""
    field_name = request.query_one("field", "") or ""
    if not field_name:
        raise InvalidRequest("field is required")
    return Response.json(200, runtime.discovery.get(dataset, field_name).as_dict())

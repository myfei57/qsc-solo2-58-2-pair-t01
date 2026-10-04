"""HTTP wiring tests for the discovery endpoints."""

from __future__ import annotations

import json
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from maskhub.console.errors import error_response
from maskhub.console.http import Request
from maskhub.console.runtime import build_runtime
from maskhub.console.routes import build_router
from maskhub.store.kvstore import RecordStore


def call(router, method: str, target: str, payload: dict | None = None) -> tuple[int, dict]:
    parsed = urlsplit(target)
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    request = Request(
        method,
        parsed.path,
        parse_qs(parsed.query, keep_blank_values=True),
        {},
        body,
    )
    try:
        response = router.dispatch(request)
    except Exception as exc:
        response = error_response(exc)
    return response.status, json.loads(response.payload.decode("utf-8"))


class DiscoveryHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        store = RecordStore(self._tmp.name)
        store.load()
        runtime = build_runtime(store)
        self.router = build_router(runtime)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_scan_review_confirm_flow(self) -> None:
        columns = [
            {"name": "email", "samples": [f"u{i}@example.com" for i in range(8)]},
            # Named like email but only partly shaped: genuinely ambiguous.
            {"name": "backup_email", "samples": ["a@b.com", "c@d.com", "x", "y", "z", "w"]},
        ]

        status, report = call(self.router, "POST", "/discovery/scan", {
            "dataset": "ds", "columns": columns,
        })
        self.assertEqual(status, 200)
        self.assertEqual(report["scanned"], 2)

        status, queued = call(self.router, "GET", "/discovery/review?dataset=ds")
        self.assertEqual(status, 200)
        self.assertEqual(
            {item["field_name"] for item in queued["pending"]}, {"backup_email"}
        )

        status, confirmed = call(self.router, "POST", "/discovery/confirm", {
            "dataset": "ds", "field": "backup_email",
            "sensitivity": "public", "reviewer": "ada",
        })
        self.assertEqual(status, 200)
        self.assertEqual(confirmed["origin"], "manual")

        status, queued = call(self.router, "GET", "/discovery/review?dataset=ds")
        self.assertEqual(queued["count"], 0)

    def test_scan_rejects_empty_columns(self) -> None:
        status, body = call(self.router, "POST", "/discovery/scan", {
            "dataset": "ds", "columns": [],
        })
        self.assertEqual(status, 400)
        self.assertIn("columns", body["error"])

    def test_unknown_sensitivity_rejected(self) -> None:
        call(self.router, "POST", "/discovery/scan", {
            "dataset": "ds",
            "columns": [{"name": "note", "samples": ["a", "b", "c", "d", "e"]}],
        })
        status, body = call(self.router, "POST", "/discovery/confirm", {
            "dataset": "ds", "field": "note", "sensitivity": "nope",
        })
        self.assertEqual(status, 400)

    def test_confirm_missing_verdict_is_404(self) -> None:
        status, _ = call(self.router, "POST", "/discovery/confirm", {
            "dataset": "ds", "field": "ghost", "sensitivity": "public",
        })
        self.assertEqual(status, 404)

    def test_routes_described(self) -> None:
        _, body = call(self.router, "GET", "/routes")
        self.assertTrue(any("discovery/scan" in item for item in body["routes"]))


if __name__ == "__main__":
    unittest.main()

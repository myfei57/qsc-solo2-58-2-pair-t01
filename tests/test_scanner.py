"""End-to-end scanner/registry rules: stability, drift, human protection."""

from __future__ import annotations

from tests.support import DiscoveryTestCase


EMAILS = [f"user{i}@example.com" for i in range(10)]
ORDINARY = ["red", "green", "blue", "yellow", "black", "white"]
# Named like email but only partly shaped like one: genuinely ambiguous.
AMBIGUOUS = ["a@b.com", "c@d.com", "not-an-email", "plain text", "also plain", "e@f.org"]
PHONES = ["13800138000", "13912345678", "13700001111", "13655556666"]


class ScanStabilityTest(DiscoveryTestCase):
    def test_same_shape_keeps_verdict_and_fingerprint(self) -> None:
        self.scan("ds", [{"name": "email", "samples": EMAILS}])
        first = self.verdict("ds", "email")
        self.assertEqual(first.sensitivity, "personal")
        self.assertEqual(first.origin, "auto")

        # Re-scan with different rows but the same shape (same length bands).
        second_batch = [f"person{i}@corp.org" for i in range(10)]
        report = self.scan("ds", [{"name": "email", "samples": second_batch}])
        second = self.verdict("ds", "email")
        self.assertEqual(second.fingerprint, first.fingerprint)
        self.assertEqual(second.decided_at, first.decided_at)
        self.assertEqual(report["reused"], 1)
        self.assertEqual(report["reopened"], 0)

    def test_shape_change_reopens_auto_verdict(self) -> None:
        self.scan("ds", [{"name": "contact", "samples": EMAILS}])
        before = self.verdict("ds", "contact")
        self.assertTrue(before.needs_review)
        self.assertEqual(before.suggested_sensitivity, "personal")

        # Column content genuinely changes to ordinary free text.
        report = self.scan("ds", [{"name": "contact", "samples": ORDINARY}])
        self.assertEqual(report["reopened"], 1)
        after = self.verdict("ds", "contact")
        self.assertNotEqual(after.fingerprint, before.fingerprint)

    def test_manual_confirmation_is_never_overwritten(self) -> None:
        self.scan("ds", [{"name": "email", "samples": EMAILS}])
        self.registry.confirm("ds", "email", "sensitive", "alice")
        confirmed = self.verdict("ds", "email")
        self.assertTrue(confirmed.is_confirmed)
        self.assertEqual(confirmed.sensitivity, "sensitive")

        # Even a scan whose shape drifts must leave the confirmation intact.
        report = self.scan("ds", [{"name": "email", "samples": ORDINARY}])
        still = self.verdict("ds", "email")
        self.assertEqual(still.sensitivity, "sensitive")
        self.assertEqual(still.origin, "manual")
        self.assertEqual(still.decided_by, "alice")
        self.assertEqual(report["confirmed_preserved"], 1)
        self.assertEqual(report["reopened"], 0)
        self.assertEqual(report["confirmed_drift"], ["email"])

    def test_confirmed_same_shape_is_preserved_without_drift_flag(self) -> None:
        self.scan("ds", [{"name": "email", "samples": EMAILS}])
        self.registry.confirm("ds", "email", "sensitive", "alice")
        report = self.scan("ds", [{"name": "email", "samples": EMAILS}])
        self.assertEqual(report["confirmed_preserved"], 1)
        self.assertEqual(report["confirmed_drift"], [])

    def test_review_decision_is_reused_on_next_scan(self) -> None:
        # Ambiguous column: name says email, only part of the shape agrees.
        self.scan("ds", [{"name": "email", "samples": AMBIGUOUS}])
        first = self.verdict("ds", "email")
        self.assertTrue(first.needs_review)

        report = self.scan("ds", [{"name": "email", "samples": AMBIGUOUS}])
        second = self.verdict("ds", "email")
        # Still queued, but no fresh decision run: reused, not re-created.
        self.assertTrue(second.needs_review)
        self.assertEqual(second.decided_at, first.decided_at)
        self.assertEqual(report["reused"], 1)
        self.assertEqual(report["pending_review"], 1)

    def test_review_queue_lists_only_risky_columns(self) -> None:
        self.scan(
            "ds",
            [
                {"name": "email", "samples": EMAILS},        # high, not queued
                {"name": "email2", "samples": AMBIGUOUS},    # risky guess, queued
                {"name": "color", "samples": ORDINARY},      # ordinary, not queued
            ],
        )
        queued = {item["field_name"] for item in self.registry.review_queue("ds")}
        self.assertEqual(queued, {"email2"})

    def test_ordinary_column_stays_unknown_without_filling_queue(self) -> None:
        self.scan("ds", [{"name": "color", "samples": ORDINARY}])
        self.assertEqual(self.registry.review_queue("ds"), [])
        verdict = self.verdict("ds", "color")
        self.assertEqual(verdict.sensitivity, "unknown")
        self.assertFalse(verdict.is_actionable)

    def test_confirm_clears_queue(self) -> None:
        self.scan("ds", [{"name": "email2", "samples": AMBIGUOUS}])
        self.assertEqual(len(self.registry.review_queue("ds")), 1)
        self.registry.confirm("ds", "email2", "personal", "bob")
        self.assertEqual(self.registry.review_queue("ds"), [])
        self.assertEqual(self.verdict("ds", "email2").sensitivity, "personal")

    def test_confirm_unknown_sensitivity_rejected(self) -> None:
        self.scan("ds", [{"name": "email2", "samples": AMBIGUOUS}])
        with self.assertRaises(Exception):
            self.registry.confirm("ds", "email2", "topsecret", "bob")

    def test_release_reopens_review(self) -> None:
        self.scan("ds", [{"name": "email", "samples": EMAILS}])
        self.registry.confirm("ds", "email", "sensitive", "alice")
        released = self.registry.release_to_review("ds", "email", "alice")
        self.assertTrue(released.needs_review)
        self.assertEqual(released.origin, "auto")
        self.assertEqual(released.suggested_sensitivity, "sensitive")

    def test_verdicts_persist_across_registry_instances(self) -> None:
        self.scan("ds", [{"name": "email", "samples": EMAILS}])
        self.registry.confirm("ds", "email", "sensitive", "alice")

        from maskhub.console.runtime import build_runtime

        rebuilt = build_runtime(self.runtime.store)
        verdict = rebuilt.discovery.get("ds", "email")
        self.assertEqual(verdict.origin, "manual")
        self.assertEqual(verdict.sensitivity, "sensitive")
        # Stable fingerprint travels with the stored verdict.
        self.assertTrue(verdict.fingerprint)

    def test_scan_does_not_require_or_create_dataset_catalog(self) -> None:
        # Discovery runs on a source/dataset identifier before catalog
        # registration exists; it must not mutate catalog state.
        report = self.scan("ingest-only", [{"name": "email", "samples": EMAILS}])
        self.assertEqual(report["scanned"], 1)
        self.assertEqual(self.runtime.datasets.identifiers(), [])


class PromoteTest(DiscoveryTestCase):
    def _register_dataset(self, identifier: str = "ds") -> None:
        from maskhub.catalog.dataset import Dataset
        from maskhub.catalog.field import Field
        from maskhub.source.registry import Source, SourceStatus

        self.runtime.sources.register(Source(identifier="src", kind="file", endpoint="/tmp/x"))
        self.runtime.sources.set_status("src", SourceStatus.ACTIVE)
        self.runtime.datasets.save(
            Dataset(
                identifier=identifier,
                source="src",
                owner="carol",
                fields=(Field(name="id", sensitivity="public", declared_by="carol"),),
            )
        )

    def test_promote_adds_only_actionable_verdicts(self) -> None:
        self._register_dataset()
        self.scan(
            "ds",
            [
                {"name": "email", "samples": EMAILS},       # high -> promoted
                {"name": "email2", "samples": AMBIGUOUS},   # pending -> skipped
            ],
        )
        result = self.scanner.promote("ds", "discovery", self.runtime.datasets)
        self.assertEqual(result["promoted"], ["email"])
        reasons = {item["field"]: item["reason"] for item in result["skipped"]}
        self.assertIn("email2", reasons)

        dataset = self.runtime.datasets.get("ds")
        by_name = {item.name: item for item in dataset.fields}
        self.assertEqual(by_name["email"].sensitivity, "personal")
        self.assertEqual(by_name["email"].declared_by, "discovery")
        # Pre-existing manual field is untouched.
        self.assertEqual(by_name["id"].declared_by, "carol")

    def test_promote_never_overwrites_existing_catalog_field(self) -> None:
        self._register_dataset()
        self.scan("ds", [{"name": "id", "samples": EMAILS}])
        self.registry.confirm("ds", "id", "sensitive", "alice")
        result = self.scanner.promote("ds", "discovery", self.runtime.datasets)
        self.assertEqual(result["promoted"], [])
        field = self.runtime.datasets.get("ds").field("id")
        self.assertEqual(field.sensitivity, "public")
        self.assertEqual(field.declared_by, "carol")


if __name__ == "__main__":
    import unittest

    unittest.main()

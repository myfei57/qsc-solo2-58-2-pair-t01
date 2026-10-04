import tempfile
import unittest

from maskhub.catalog.dataset import Dataset
from maskhub.catalog.field import Field
from maskhub.discovery.registry import (
    DiscoveryArchive,
    ORIGIN_MANUAL,
    STATE_CONFIRMED,
    STATE_REJECTED,
)
from maskhub.discovery.publishing import DISCOVERY_PREFIX, publish_to_catalog
from maskhub.catalog.dataset import DatasetRegistry
from maskhub.discovery.scanner import STATUS_AUTO
from maskhub.store.kvstore import RecordStore

EMAILS = ["alice@example.com", "bob@corp.cn", "carol@mail.io"] * 4
EMAILS_2 = ["dave@other.org", "erin@mail.net", "frank@host.com"] * 4
PHONES = ["13800138000", "15912345678", "18677778888"] * 4


def archive_in_temp():
    tmp = tempfile.TemporaryDirectory()
    store = RecordStore(tmp.name)
    store.load()
    return tmp, store, DiscoveryArchive(store)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.archive = archive_in_temp()

    def tearDown(self):
        self.tmp.cleanup()

    def _record(self, report, column):
        return next(item for item in report["columns"] if item["column"] == column)

    def test_first_scan_reports_auto_and_review_buckets(self):
        report = self.archive.scan(
            "ds",
            [("user_email", EMAILS), ("remark", ["张三", "李四"] * 4)],
        )
        self.assertIn("user_email", report["auto_confirmed"])
        self.assertIn("remark", report["needs_review"])

    def test_verdict_stable_when_shape_unchanged(self):
        first = self.archive.scan("ds", [("user_email", EMAILS)])
        second = self.archive.scan("ds", [("user_email", EMAILS_2)])
        self.assertEqual(second["verdicts_reused"], ["user_email"])
        self.assertEqual(second["verdicts_reevaluated"], [])
        self.assertEqual(
            self._record(first, "user_email")["category"],
            self._record(second, "user_email")["category"],
        )
        self.assertEqual(
            self._record(first, "user_email")["confidence"],
            self._record(second, "user_email")["confidence"],
        )

    def test_verdict_changes_when_shape_really_changes(self):
        self.archive.scan("ds", [("col", EMAILS)])
        report = self.archive.scan("ds", [("col", PHONES)])
        self.assertEqual(report["verdicts_reevaluated"], ["col"])
        self.assertEqual(self._record(report, "col")["category"], "cn_mobile")
        self.assertIn("col", report["shape_drift"])

    def test_confirmed_verdict_is_locked_across_scans(self):
        self.archive.scan("ds", [("col", EMAILS)])
        self.archive.decide("ds", "col", STATE_CONFIRMED, "alice", sensitivity="sensitive")
        report = self.archive.scan("ds", [("col", PHONES)])
        record = self._record(report, "col")
        self.assertEqual(record["origin"], ORIGIN_MANUAL)
        self.assertEqual(record["sensitivity"], "sensitive")  # not overwritten
        self.assertEqual(record["category"], "email")
        self.assertTrue(record["drift"])
        self.assertIn("col", report["shape_drift"])
        self.assertIn("col", report["manual_verdicts_kept"])

    def test_drift_disappears_after_reconfirming_against_new_shape(self):
        self.archive.scan("ds", [("col", EMAILS)])
        self.archive.decide("ds", "col", STATE_CONFIRMED, "alice")
        self.archive.scan("ds", [("col", PHONES)])
        record = self.archive.decide("ds", "col", STATE_CONFIRMED, "alice")
        self.assertFalse(record["drift"])

    def test_rejected_verdict_is_locked(self):
        self.archive.scan("ds", [("col", ["张三", "李四"] * 4)])
        self.archive.decide("ds", "col", STATE_REJECTED, "bob")
        report = self.archive.scan("ds", [("col", ["王五", "赵六"] * 4)])
        record = self._record(report, "col")
        self.assertEqual(record["status"], STATE_REJECTED)
        self.assertEqual(record["sensitivity"], "public")

    def test_reviewed_verdict_reused_next_scan(self):
        first = self.archive.scan("ds", [("remark", ["张三", "李四"] * 4)])
        self.archive.decide("ds", "remark", STATE_CONFIRMED, "carol")
        second = self.archive.scan("ds", [("remark", ["钱七", "孙八"] * 4)])
        # same shape -> the manual verdict is reused, no re-evaluation
        self.assertIn("remark", second["manual_verdicts_kept"])
        self.assertNotIn("remark", second["verdicts_reevaluated"])

    def test_absent_columns_are_kept_not_deleted(self):
        self.archive.scan("ds", [("a", EMAILS), ("b", PHONES)])
        report = self.archive.scan("ds", [("a", EMAILS)])
        self.assertEqual(report["absent_columns"], ["b"])
        self.assertEqual({c["column"] for c in report["columns"]}, {"a", "b"})

    def test_review_queue_only_contains_uncertain_and_drifted(self):
        self.archive.scan(
            "ds",
            [("user_email", EMAILS), ("remark", ["张三", "李四"] * 4)],
        )
        queue = self.archive.review_queue()
        self.assertEqual([item["column"] for item in queue], ["remark"])

        self.archive.decide("ds", "remark", STATE_CONFIRMED, "alice")
        # confirmed verdict on changed data re-enters the queue via drift
        self.archive.scan("ds", [("remark", PHONES)])
        queue = self.archive.review_queue()
        self.assertEqual([item["column"] for item in queue], ["remark"])

    def test_drifted_auto_verdict_re_enters_review_queue(self):
        self.archive.scan("ds", [("col", EMAILS)])
        self.archive.scan("ds", [("col", PHONES)])
        queue = self.archive.review_queue()
        self.assertEqual([item["column"] for item in queue], ["col"])
        self.assertIn("auto_verdict_shape_drift", queue[0]["review_reasons"])

    def test_absent_manual_column_keeps_locked_verdict_metadata(self):
        self.archive.scan("ds", [("a", EMAILS), ("b", PHONES)])
        self.archive.decide("ds", "b", STATE_CONFIRMED, "alice", sensitivity="special")
        report = self.archive.scan("ds", [("a", EMAILS)])  # b absent
        record = next(item for item in report["columns"] if item["column"] == "b")
        self.assertEqual(record["origin"], ORIGIN_MANUAL)
        self.assertEqual(record["sensitivity"], "special")
        self.assertEqual(record["status"], STATE_CONFIRMED)

    def test_ruleset_change_forces_reevaluation_even_without_drift(self):
        first = self.archive.scan("ds", [("user_email", EMAILS)], rule_version="rules-v1")
        self.assertEqual(first["rule_version"], "rules-v1")
        second = self.archive.scan("ds", [("user_email", EMAILS)], rule_version="rules-v2")
        self.assertIn("user_email", second["verdicts_reevaluated"])

    def test_scan_does_not_mutate_input_samples(self):
        samples = [" Alice@Example.COM ", None, "bob@corp.cn"]
        snapshot = list(samples)
        self.archive.scan("ds", [("user_email", samples)])
        self.assertEqual(samples, snapshot)

    def test_decide_unknown_column_raises(self):
        self.archive.scan("ds", [("a", EMAILS)])
        with self.assertRaises(Exception):
            self.archive.decide("ds", "missing", STATE_CONFIRMED, "alice")


class PublishingTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.archive = archive_in_temp()
        self.datasets = DatasetRegistry(self.store)
        self.datasets.save(
            Dataset(
                identifier="ds",
                source="src",
                owner="dpo",
                fields=(
                    Field(name="hand_curated", sensitivity="special", declared_by="alice"),
                    Field(name="old_guess", sensitivity="sensitive",
                          declared_by=DISCOVERY_PREFIX + "auto_confirmed"),
                ),
            )
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_publish_propagates_auto_verdicts_and_protects_human_fields(self):
        self.archive.scan("ds", [("user_email", EMAILS), ("hand_curated", PHONES)])
        result = publish_to_catalog(self.archive, self.datasets, "ds")
        by_name = {field.name: field for field in self.datasets.get("ds").fields}

        self.assertEqual(by_name["hand_curated"].sensitivity, "special")
        self.assertEqual(by_name["hand_curated"].declared_by, "alice")
        self.assertEqual(by_name["user_email"].sensitivity, "personal")
        self.assertEqual(by_name["user_email"].declared_by,
                         DISCOVERY_PREFIX + STATUS_AUTO)
        # stale managed field dropped (no longer present in scan)
        self.assertNotIn("old_guess", by_name)
        self.assertIn("hand_curated", result["human_fields_protected"])

    def test_publish_then_republish_never_touches_human_field(self):
        self.archive.scan("ds", [("hand_curated", EMAILS)])
        publish_to_catalog(self.archive, self.datasets, "ds")
        field = next(f for f in self.datasets.get("ds").fields if f.name == "hand_curated")
        self.assertEqual(field.sensitivity, "special")

    def test_rejected_columns_publish_as_public_managed(self):
        self.archive.scan("ds", [("remark", ["张三", "李四"] * 4)])
        self.archive.decide("ds", "remark", STATE_REJECTED, "alice")
        publish_to_catalog(self.archive, self.datasets, "ds")
        field = next(f for f in self.datasets.get("ds").fields if f.name == "remark")
        self.assertEqual(field.sensitivity, "public")
        self.assertEqual(field.declared_by, DISCOVERY_PREFIX + STATE_REJECTED)


if __name__ == "__main__":
    unittest.main()

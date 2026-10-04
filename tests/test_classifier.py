"""Classifier unit tests: dual evidence, confidence bands, conflicts."""

from __future__ import annotations

import unittest

from maskhub.discovery.classifier import classify
from maskhub.discovery.profile import profile_column


def decide(name: str, values: list[object]):
    return classify(profile_column(name, values), values)


class ClassifierTest(unittest.TestCase):
    def test_name_and_samples_agree_is_high_confidence(self) -> None:
        emails = [f"user{i}@example.com" for i in range(10)]
        decision = decide("email", emails)
        self.assertEqual(decision.sensitivity, "personal")
        self.assertEqual(decision.confidence, "high")
        self.assertFalse(decision.review_required)
        self.assertTrue(any("column name" in item for item in decision.evidence))
        self.assertTrue(any("samples match" in item for item in decision.evidence))

    def test_shape_only_email_stays_medium_and_needs_review(self) -> None:
        emails = [f"user{i}@example.com" for i in range(10)]
        decision = decide("contact_info", emails)
        self.assertTrue(decision.review_required)
        self.assertEqual(decision.sensitivity, "unknown")
        self.assertEqual(decision.suggested_sensitivity, "personal")
        self.assertEqual(decision.confidence, "medium")

    def test_name_only_free_text_needs_review(self) -> None:
        values = ["张三", "李四", "王五", "赵六"]
        decision = decide("user_name", values)
        # Free-text name detector has no shape signal; it cannot be auto-applied.
        self.assertEqual(decision.suggested_sensitivity, "personal")
        self.assertTrue(decision.review_required)
        self.assertEqual(decision.confidence, "medium")

    def test_unknown_column_recorded_but_not_forced_into_review(self) -> None:
        values = ["red", "green", "blue", "yellow"]
        decision = decide("color", values)
        self.assertEqual(decision.sensitivity, "unknown")
        # No sensitivity signal: ordinary column, must not burn reviewer time.
        self.assertFalse(decision.review_required)

    def test_too_few_samples_requires_review(self) -> None:
        decision = decide("email", ["a@b.com", "c@d.com"])
        self.assertEqual(decision.sensitivity, "unknown")
        self.assertTrue(decision.review_required)
        self.assertTrue(any("sample too small" in item for item in decision.evidence))

    def test_empty_column_requires_review(self) -> None:
        decision = decide("email", [None, "", "  "])
        self.assertEqual(decision.sensitivity, "unknown")
        self.assertTrue(decision.review_required)

    def test_chinese_id_card_is_special(self) -> None:
        # Valid GB 11643 numbers (correct checksum digits).
        values = [
            "110105199003070017",
            "110105199003070025",
            "110105199003070172",
        ]
        decision = decide("id_card_no", values)
        self.assertEqual(decision.sensitivity, "special")
        self.assertFalse(decision.review_required)
        self.assertTrue(any("identity" in item for item in decision.evidence))

    def test_public_postal_code(self) -> None:
        values = ["100000", "200000", "518000", "310000"]
        decision = decide("postcode", values)
        self.assertEqual(decision.sensitivity, "public")
        self.assertFalse(decision.review_required)

    def test_password_name_is_special(self) -> None:
        values = ["x", "y", "z", "w"]
        decision = decide("password", values)
        self.assertEqual(decision.suggested_sensitivity, "special")
        self.assertTrue(decision.review_required)

    def test_evidence_always_present_for_auto_decision(self) -> None:
        values = [f"user{i}@example.com" for i in range(6)]
        decision = decide("email", values)
        self.assertTrue(decision.evidence)


if __name__ == "__main__":
    unittest.main()

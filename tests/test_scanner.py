import unittest

from maskhub.discovery.scanner import (
    AUTO_CONFIRM,
    scan_column,
    STATUS_AUTO,
    STATUS_REVIEW,
    STATUS_UNDETERMINED,
)

CNID = "11010519491231002X"
BANK_CARD = "6225880212345673"


def repeat(values, times):
    return values * times


class ScannerVerdictTests(unittest.TestCase):
    def test_email_double_signal_auto_confirms_with_evidence(self):
        result = scan_column(
            "user_email",
            repeat(["alice@example.com", "bob@corp.cn", "carol@mail.io"], 4),
        )
        finding = result.finding
        self.assertEqual(finding.category, "email")
        self.assertEqual(finding.sensitivity, "personal")
        self.assertEqual(finding.status, STATUS_AUTO)
        self.assertGreaterEqual(finding.confidence, AUTO_CONFIRM)
        channels = {item.channel for item in finding.evidence}
        self.assertEqual(channels, {"name", "value"})

    def test_value_only_hard_shape_auto_confirms(self):
        result = scan_column("col_a", repeat(["13800138000", "15912345678"], 6))
        self.assertEqual(result.finding.category, "cn_mobile")
        self.assertEqual(result.finding.status, STATUS_AUTO)

    def test_cnid_checksum_validator_promotes_special_category(self):
        result = scan_column("sfzh", [CNID] * 10)
        self.assertEqual(result.finding.category, "cn_id_card")
        self.assertEqual(result.finding.sensitivity, "special")
        self.assertEqual(result.finding.status, STATUS_AUTO)
        self.assertTrue(
            any(item.signal == "value_validated" for item in result.finding.evidence)
        )

    def test_shape_without_checksum_is_not_id_card(self):
        result = scan_column("sfzh", ["110105194912310020"] * 10)
        self.assertNotEqual(result.finding.category, "cn_id_card")

    def test_luhn_required_for_bank_card(self):
        self.assertEqual(scan_column("card_no", [BANK_CARD] * 10).finding.category,
                         "bank_card")
        self.assertNotEqual(
            scan_column("card_no", ["6225880212345670"] * 10).finding.category,
            "bank_card",
        )

    def test_loose_name_shape_without_supporting_column_goes_to_review(self):
        result = scan_column("col_people", ["张三", "李四", "王小明"] * 4)
        self.assertEqual(result.finding.category, "person_name")
        self.assertEqual(result.finding.status, STATUS_REVIEW)

    def test_strong_name_plus_loose_shape_auto_confirms(self):
        result = scan_column("cust_name", ["张三", "李四", "王小明"] * 4)
        self.assertEqual(result.finding.category, "person_name")
        self.assertEqual(result.finding.status, STATUS_AUTO)

    def test_excluded_column_name_demotes_date_shape(self):
        result = scan_column("created_at", ["2021-01-01", "2022-03-04"] * 6)
        self.assertEqual(result.finding.category, "")
        self.assertEqual(result.finding.sensitivity, "public")

    def test_birthday_column_still_detected(self):
        result = scan_column("birthday", ["2000-02-29", "1998-11-05"] * 6)
        self.assertEqual(result.finding.category, "birth_date")

    def test_free_text_defaults_to_public(self):
        result = scan_column(
            "note",
            repeat(
                [
                    "hello world this is free text",
                    "another ordinary sentence here",
                    "nothing special in this content",
                ],
                4,
            ),
        )
        self.assertEqual(result.finding.category, "")
        self.assertEqual(result.finding.sensitivity, "public")
        self.assertEqual(result.finding.status, STATUS_AUTO)

    def test_empty_column_is_undetermined_not_public(self):
        result = scan_column("blank", [None, "", "  "] * 4)
        self.assertEqual(result.finding.status, STATUS_UNDETERMINED)
        self.assertEqual(result.finding.confidence, 0.0)

    def test_too_few_samples_go_to_review(self):
        result = scan_column("col_x", ["13800138000", "15912345678"])
        self.assertEqual(result.finding.category, "cn_mobile")
        self.assertEqual(result.finding.status, STATUS_UNDETERMINED)
        self.assertTrue(
            any(item.signal == "insufficient_samples" for item in result.finding.evidence)
        )

    def test_confidence_bounded_and_evidence_present(self):
        result = scan_column("a", [])
        self.assertTrue(result.finding.evidence)
        result2 = scan_column("user_email", ["bad-data", "also-bad"] * 4)
        for evidence in result2.finding.evidence:
            self.assertGreaterEqual(evidence.weight, 0.0)
            self.assertLessEqual(evidence.weight, 1.0)

    def test_scan_is_deterministic(self):
        columns = [("user_email", repeat(["a@b.com", "c@d.cn"], 6))]
        first = scan_column(*columns[0]).finding.as_dict()
        second = scan_column(*columns[0]).finding.as_dict()
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

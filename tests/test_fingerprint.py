import unittest

from maskhub.discovery.fingerprint import fingerprint_values, shape_of


class FingerprintTests(unittest.TestCase):
    def test_shape_masks_actual_characters(self):
        self.assertEqual(shape_of("alice@example.com"), "a@a.a")
        self.assertEqual(shape_of("13800138000"), "9")
        self.assertEqual(shape_of("北京市海淀区1号"), "C9C")

    def test_same_shape_same_signature_across_values(self):
        left = fingerprint_values(["alice@example.com", "bob@corp.cn"] * 6)
        right = fingerprint_values(["dave@other.org", "erin@mail.net"] * 6)
        self.assertEqual(left.signature(), right.signature())

    def test_changed_shape_changes_signature(self):
        emails = fingerprint_values(["alice@example.com"] * 12)
        phones = fingerprint_values(["13800138000"] * 12)
        self.assertNotEqual(emails.signature(), phones.signature())

    def test_small_perturbations_keep_bucketed_signature(self):
        base = fingerprint_values([str(1000 + i) for i in range(20)])
        shifted = fingerprint_values([str(2000 + i) for i in range(20)])
        self.assertEqual(base.signature(), shifted.signature())

    def test_empty_columns_have_stable_signature(self):
        self.assertEqual(
            fingerprint_values(["", None]).signature(),
            fingerprint_values([None, "   "]).signature(),
        )

    def test_fingerprint_roundtrip(self):
        fingerprint = fingerprint_values(["a@b.com", "c@d.cn"])
        restored = fingerprint.from_dict(fingerprint.as_dict())
        self.assertIsNotNone(restored)
        self.assertEqual(restored.signature(), fingerprint.signature())


if __name__ == "__main__":
    unittest.main()

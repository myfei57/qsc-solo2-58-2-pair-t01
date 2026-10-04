import tempfile
import unittest

from maskhub.discovery.registry import DiscoveryArchive
from maskhub.store.kvstore import RecordStore

EMAILS = ["alice@example.com", "bob@corp.cn"] * 6
PHONES = ["13800138000", "15912345678"] * 6


class NoRawDataPersistedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = RecordStore(self.tmp.name)
        self.store.load()
        self.archive = DiscoveryArchive(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_archive_documents_contain_no_sample_values(self):
        self.archive.scan(
            "secret",
            [("email_col", EMAILS), ("phone_col", PHONES), ("note_col", ["机密文本A", "机密文本B"] * 4)],
        )
        raw_files = list(__import__("pathlib").Path(self.tmp.name).glob("*.json"))
        self.assertTrue(raw_files)
        for path in raw_files:
            blob = path.read_text("utf-8")
            for secret in (*EMAILS, *PHONES, "机密文本A", "机密文本B"):
                self.assertNotIn(secret, blob, f"{secret} leaked into {path.name}")

    def test_scan_never_writes_to_submitted_samples(self):
        samples = [13800138000, None, " bob@corp.cn "]
        snapshot = list(samples)
        self.archive.scan("ds", [("x", samples)])
        self.assertEqual(samples, snapshot)


if __name__ == "__main__":
    unittest.main()

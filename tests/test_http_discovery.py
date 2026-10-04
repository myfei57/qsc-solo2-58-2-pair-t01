import json
import tempfile
import threading
import unittest
import urllib.request

from maskhub.bootstrap import create_server
from maskhub.config import Settings
from maskhub.console.http import Request


def post(server, path, payload):
    url = f"{server.url}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def get(server, path):
    with urllib.request.urlopen(f"{server.url}{path}") as response:
        return response.status, json.loads(response.read().decode("utf-8"))


class DiscoveryHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        settings = Settings(data_dir=self.tmp.name, host="127.0.0.1", port=0)
        self.server = create_server(settings)
        self.server.start()
        self._port = self.server.address[1]

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def test_scan_review_decide_flow(self):
        emails = ["alice@example.com", "bob@corp.cn", "carol@mail.io"] * 4
        status, report = post(self.server, "/discovery/scan", {
            "dataset": "crm",
            "columns": [
                {"name": "user_email", "samples": emails},
                {"name": "remark", "samples": ["张三", "李四"] * 4},
            ],
        })
        self.assertEqual(status, 200)
        self.assertIn("user_email", report["auto_confirmed"])
        self.assertIn("remark", report["needs_review"])

        _, queue = get(self.server, "/discovery/review")
        self.assertEqual([c["column"] for c in queue["columns"]], ["remark"])

        status, decided = post(self.server, "/discovery/decide", {
            "dataset": "crm",
            "column": "remark",
            "decision": "confirmed",
            "reviewer": "dpo@corp",
            "sensitivity": "public",
            "note": "generic remarks",
        })
        self.assertEqual(status, 200)
        self.assertEqual(decided["sensitivity"], "public")

        # rescan with same-shape values keeps the human decision
        _, again = post(self.server, "/discovery/scan", {
            "dataset": "crm",
            "columns": [
                {"name": "user_email", "samples": ["d@other.org", "e@mail.net"] * 6},
                {"name": "remark", "samples": ["王五", "赵六"] * 4},
            ],
        })
        self.assertIn("remark", again["manual_verdicts_kept"])
        self.assertEqual(again["verdicts_reused"], ["user_email"])

    def test_status_requires_scanned_dataset(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            get(self.server, "/discovery/status?dataset=ghost")
        self.assertEqual(ctx.exception.code, 404)

    def test_categories_endpoint(self):
        status, payload = get(self.server, "/discovery/categories")
        self.assertEqual(status, 200)
        self.assertTrue(payload["rule_version"].startswith("builtin-"))
        ids = {c["identifier"] for c in payload["categories"]}
        self.assertIn("cn_id_card", ids)


if __name__ == "__main__":
    unittest.main()

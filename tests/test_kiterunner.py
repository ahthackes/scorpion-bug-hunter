import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.kiterunner import KiterunnerModule  # noqa: E402

SAMPLE_OUTPUT = "\n".join([
    json.dumps({"url": "https://example.com/api/v1/users", "method": "GET", "status_code": 200}),
    json.dumps({"url": "https://example.com/api/v1/users", "method": "GET", "status_code": 200}),
])


class KiterunnerParseTestCase(unittest.TestCase):
    def test_parses_and_dedupes_routes(self):
        module = KiterunnerModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].meta["method"], "GET")

    def test_empty_output_returns_no_assets(self):
        module = KiterunnerModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_line_is_skipped(self):
        module = KiterunnerModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

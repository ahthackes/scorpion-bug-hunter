"""Tests for modules.recon.gau's parse() logic -- handles both JSON-lines
(gau --json) and plain-text (waybackurls fallback) output in the same
parser.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.gau import GauModule  # noqa: E402

JSON_OUTPUT = """
{"url": "https://example.com/login?next=/a"}
{"url": "https://example.com/api/v1/users"}
{"url": "https://example.com/login?next=/a"}
""".strip()

PLAIN_OUTPUT = "https://example.com/login\nhttps://example.com/api/v1/users\n"


class GauParseTestCase(unittest.TestCase):
    def test_parses_json_lines(self):
        module = GauModule()
        assets = module.parse(JSON_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)  # dupe collapsed
        self.assertTrue(all(a.type == AssetType.ENDPOINT for a in assets))

    def test_parses_plaintext_fallback(self):
        module = GauModule()
        assets = module.parse(PLAIN_OUTPUT, target_raw="example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://example.com/api/v1/users", "https://example.com/login"])

    def test_empty_output(self):
        module = GauModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

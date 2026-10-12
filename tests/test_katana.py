"""Tests for modules.recon.katana's parse() logic (both JSON-lines and
the hakrawler plain-text fallback), using saved sample output instead of
calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.katana import KatanaModule  # noqa: E402

JSON_OUTPUT = """
{"request": {"endpoint": "https://example.com/login"}}
{"request": {"endpoint": "https://example.com/admin"}}
{"request": {"endpoint": "https://example.com/login"}}
""".strip()

PLAIN_OUTPUT = """
https://example.com/login
https://example.com/admin
https://example.com/login
""".strip()


class KatanaParseTestCase(unittest.TestCase):
    def test_parses_jsonlines_output(self):
        module = KatanaModule()
        assets = module.parse(JSON_OUTPUT, target_raw="https://example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://example.com/admin", "https://example.com/login"])

    def test_parses_plaintext_hakrawler_fallback_output(self):
        module = KatanaModule()
        assets = module.parse(PLAIN_OUTPUT, target_raw="https://example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://example.com/admin", "https://example.com/login"])

    def test_dedupes_repeated_endpoints(self):
        module = KatanaModule()
        assets = module.parse(JSON_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 2)

    def test_asset_type_and_discovered_by(self):
        module = KatanaModule()
        assets = module.parse(PLAIN_OUTPUT, target_raw="https://example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.ENDPOINT)
            self.assertEqual(asset.discovered_by, "katana")

    def test_empty_output_returns_no_assets(self):
        module = KatanaModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

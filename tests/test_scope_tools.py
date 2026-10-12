"""Tests for the scope-ingestion modules: bbscope and Hacker-Scoper
parse() logic.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.bbscope import BbscopeModule  # noqa: E402
from modules.recon.hacker_scoper import HackerScoperModule  # noqa: E402

BBSCOPE_OUTPUT = "*.example.com\napi.example.com\n*.example.com\n"
HACKER_SCOPER_OUTPUT = "https://app.example.com/login\nhttps://api.example.com/v1\n"


class BbscopeParseTestCase(unittest.TestCase):
    def test_parses_and_dedupes_scope_entries(self):
        module = BbscopeModule()
        assets = module.parse(BBSCOPE_OUTPUT, target_raw="acme-corp")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["*.example.com", "api.example.com"])

    def test_tags_entries_with_program_name(self):
        module = BbscopeModule()
        assets = module.parse(BBSCOPE_OUTPUT, target_raw="acme-corp")
        self.assertTrue(all(a.meta["program"] == "acme-corp" for a in assets))
        self.assertTrue(all(a.type == AssetType.DOMAIN for a in assets))


class HackerScoperParseTestCase(unittest.TestCase):
    def test_parses_in_scope_urls(self):
        module = HackerScoperModule()
        assets = module.parse(HACKER_SCOPER_OUTPUT, target_raw="candidates.txt")
        self.assertEqual(len(assets), 2)
        self.assertTrue(all(a.meta["in_scope"] for a in assets))
        self.assertTrue(all(a.type == AssetType.URL for a in assets))

    def test_empty_output_means_nothing_in_scope(self):
        module = HackerScoperModule()
        self.assertEqual(module.parse("", target_raw="candidates.txt"), [])


if __name__ == "__main__":
    unittest.main()

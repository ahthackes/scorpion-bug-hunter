"""Tests for modules.recon.puredns's parse() logic, using saved sample
output instead of calling the real binary, plus run()'s guard-rail when
the wordlist/resolvers files it needs aren't present.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType, ToolError  # noqa: E402
from modules.recon.puredns import PurednsModule  # noqa: E402

SAMPLE_OUTPUT = """
www.example.com
mail.example.com
www.example.com
""".strip()


class PurednsParseTestCase(unittest.TestCase):
    def test_parses_plaintext_hostnames_into_subdomain_assets(self):
        module = PurednsModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["mail.example.com", "www.example.com"])

    def test_dedupes_repeated_hostnames(self):
        module = PurednsModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)

    def test_asset_type_and_discovered_by(self):
        module = PurednsModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.SUBDOMAIN)
            self.assertEqual(asset.discovered_by, "puredns")

    def test_empty_output_returns_no_assets(self):
        module = PurednsModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_run_raises_tool_error_when_wordlist_missing(self):
        module = PurednsModule()
        config = {"tiers": {"tier1": {"puredns_wordlist": "/no/such/wordlist.txt"}}}
        with self.assertRaises(ToolError):
            module.run("example.com", config)

    def test_run_raises_tool_error_when_resolvers_missing(self):
        module = PurednsModule()
        config = {
            "tiers": {
                "tier1": {
                    "puredns_wordlist": "config/wordlists/subdomains-small.txt",
                    "puredns_resolvers": "/no/such/resolvers.txt",
                }
            }
        }
        with self.assertRaises(ToolError):
            module.run("example.com", config)


if __name__ == "__main__":
    unittest.main()

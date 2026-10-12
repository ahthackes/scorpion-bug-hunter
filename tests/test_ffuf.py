"""Tests for modules.recon.ffuf's parse() logic, using saved sample JSON
output instead of calling the real binary, plus run()'s guard-rail when
the wordlist is missing.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType, ToolError  # noqa: E402
from modules.recon.ffuf import FfufModule  # noqa: E402

SAMPLE_OUTPUT = """
{
  "results": [
    {"url": "https://example.com/admin", "status": 200, "length": 512},
    {"url": "https://example.com/backup", "status": 403, "length": 10}
  ]
}
""".strip()


class FfufParseTestCase(unittest.TestCase):
    def test_parses_results_into_endpoint_assets(self):
        module = FfufModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://example.com/admin", "https://example.com/backup"])

    def test_asset_type_and_meta(self):
        module = FfufModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.ENDPOINT)
            self.assertEqual(asset.discovered_by, "ffuf")
            self.assertIn("status_code", asset.meta)

    def test_no_results_returns_no_assets(self):
        module = FfufModule()
        self.assertEqual(module.parse('{"results": []}', target_raw="https://example.com"), [])

    def test_empty_output_returns_no_assets(self):
        module = FfufModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_assets(self):
        module = FfufModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])

    def test_run_raises_tool_error_when_wordlist_missing(self):
        module = FfufModule()
        config = {"tiers": {"tier2": {"content_wordlist": "/no/such/wordlist.txt"}}}
        with self.assertRaises(ToolError):
            module.run("https://example.com", config)


if __name__ == "__main__":
    unittest.main()

"""Tests for modules.recon.feroxbuster's parse() logic, using saved
sample JSON-lines output instead of calling the real binary, plus
run()'s guard-rail when the wordlist is missing.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType, ToolError  # noqa: E402
from modules.recon.feroxbuster import FeroxbusterModule  # noqa: E402

SAMPLE_OUTPUT = """
{"type": "statistics", "requests": 30}
{"type": "response", "url": "https://example.com/admin", "status": 200, "content_length": 512}
{"type": "response", "url": "https://example.com/admin/login", "status": 200, "content_length": 256}
{"type": "error", "message": "connection refused"}
""".strip()


class FeroxbusterParseTestCase(unittest.TestCase):
    def test_only_response_rows_become_assets(self):
        module = FeroxbusterModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://example.com/admin", "https://example.com/admin/login"])

    def test_asset_type_and_meta(self):
        module = FeroxbusterModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.ENDPOINT)
            self.assertEqual(asset.discovered_by, "feroxbuster")
            self.assertIn("status_code", asset.meta)

    def test_empty_output_returns_no_assets(self):
        module = FeroxbusterModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_lines_are_skipped(self):
        module = FeroxbusterModule()
        assets = module.parse("not json\n" + SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 2)

    def test_run_raises_tool_error_when_wordlist_missing(self):
        module = FeroxbusterModule()
        config = {"tiers": {"tier2": {"content_wordlist": "/no/such/wordlist.txt"}}}
        with self.assertRaises(ToolError):
            module.run("https://example.com", config)


if __name__ == "__main__":
    unittest.main()

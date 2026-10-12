"""Tests for modules.recon.x8's parse() logic, using saved sample output
instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.x8 import X8Module  # noqa: E402

SAMPLE_OUTPUT = """
[
  {"url": "https://example.com/page", "method": "GET", "status": 200, "parameters": ["admin"]},
  {"url": "https://example.com/static", "method": "GET", "status": 200, "parameters": []}
]
""".strip()


class X8ParseTestCase(unittest.TestCase):
    def test_only_entries_with_parameters_become_assets(self):
        module = X8Module()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].value, "https://example.com/page")

    def test_asset_type_and_meta(self):
        module = X8Module()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(assets[0].type, AssetType.ENDPOINT)
        self.assertEqual(assets[0].discovered_by, "x8")
        self.assertEqual(assets[0].meta["params"], ["admin"])
        self.assertEqual(assets[0].meta["status_code"], 200)

    def test_single_object_is_wrapped_into_a_list(self):
        module = X8Module()
        raw = '{"url": "https://example.com/x", "parameters": ["id"]}'
        assets = module.parse(raw, target_raw="example.com")
        self.assertEqual(len(assets), 1)

    def test_empty_output_returns_no_assets(self):
        module = X8Module()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_json_returns_no_assets(self):
        module = X8Module()
        self.assertEqual(module.parse("not json", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

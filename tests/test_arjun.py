"""Tests for modules.recon.arjun's parse() logic, using saved sample
output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.arjun import ArjunModule  # noqa: E402

FLAT_LIST_OUTPUT = """
{"https://example.com/page.php": ["id", "page", "ref"]}
""".strip()

NESTED_PARAMS_OUTPUT = """
{"https://example.com/search": {"params": ["q", "sort"]}}
""".strip()


class ArjunParseTestCase(unittest.TestCase):
    def test_parses_flat_list_shape(self):
        module = ArjunModule()
        assets = module.parse(FLAT_LIST_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].value, "https://example.com/page.php")
        self.assertEqual(assets[0].meta["params"], ["id", "page", "ref"])

    def test_parses_nested_params_shape(self):
        module = ArjunModule()
        assets = module.parse(NESTED_PARAMS_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].meta["params"], ["q", "sort"])

    def test_asset_type_and_discovered_by(self):
        module = ArjunModule()
        assets = module.parse(FLAT_LIST_OUTPUT, target_raw="example.com")
        self.assertEqual(assets[0].type, AssetType.ENDPOINT)
        self.assertEqual(assets[0].discovered_by, "arjun")

    def test_url_with_no_params_is_skipped(self):
        module = ArjunModule()
        raw = '{"https://example.com/static": []}'
        self.assertEqual(module.parse(raw, target_raw="example.com"), [])

    def test_empty_output_returns_no_assets(self):
        module = ArjunModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_json_returns_no_assets(self):
        module = ArjunModule()
        self.assertEqual(module.parse("not json", target_raw="example.com"), [])

    def test_non_dict_top_level_returns_no_assets(self):
        module = ArjunModule()
        self.assertEqual(module.parse("[1, 2, 3]", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

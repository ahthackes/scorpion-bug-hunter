"""Tests for modules.recon.dnsx's parse()/resolves() logic, using saved
sample output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.dnsx import DnsxModule  # noqa: E402

SAMPLE_OUTPUT = """
{"host": "app.example.com", "a": ["1.2.3.4"], "status_code": "NOERROR"}
{"host": "www.example.com", "a": ["1.2.3.5", "1.2.3.6"], "status_code": "NOERROR"}
""".strip()


class DnsxParseTestCase(unittest.TestCase):
    def test_parses_jsonlines_into_ip_assets(self):
        module = DnsxModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["app.example.com", "www.example.com"])

    def test_asset_type_and_meta_are_set(self):
        module = DnsxModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.IP)
            self.assertEqual(asset.discovered_by, "dnsx")
            self.assertIn("a", asset.meta)

    def test_empty_output_returns_no_assets(self):
        module = DnsxModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_lines_are_skipped(self):
        module = DnsxModule()
        assets = module.parse("not json\n" + SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)


class DnsxResolvesTestCase(unittest.TestCase):
    def test_resolves_true_when_output_has_lines(self):
        module = DnsxModule()
        self.assertTrue(module.resolves(SAMPLE_OUTPUT))

    def test_resolves_false_when_output_empty(self):
        module = DnsxModule()
        self.assertFalse(module.resolves(""))
        self.assertFalse(module.resolves("   \n  \n"))


if __name__ == "__main__":
    unittest.main()

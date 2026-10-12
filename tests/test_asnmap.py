import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.asnmap import AsnmapModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps({
    "input": "example.com", "as_number": "AS13335", "as_name": "CLOUDFLARENET",
    "as_range": ["1.2.3.0/24", "1.2.4.0/24"],
})


class AsnmapParseTestCase(unittest.TestCase):
    def test_parses_each_cidr_as_its_own_asset(self):
        module = AsnmapModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual({a.value for a in assets}, {"1.2.3.0/24", "1.2.4.0/24"})
        self.assertTrue(all(a.type == AssetType.IP_RANGE for a in assets))

    def test_meta_carries_as_number_and_name(self):
        module = AsnmapModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(assets[0].meta["as_number"], "AS13335")
        self.assertEqual(assets[0].meta["as_name"], "CLOUDFLARENET")

    def test_empty_output_returns_no_assets(self):
        module = AsnmapModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_json_line_is_skipped(self):
        module = AsnmapModule()
        self.assertEqual(module.parse("not json", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

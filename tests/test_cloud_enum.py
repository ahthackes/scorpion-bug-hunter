import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.cloud_enum import CloudEnumModule, _keyword_for  # noqa: E402

SAMPLE_OUTPUT = (
    "[+] Checking for AWS buckets\n"
    "  [found] example.s3.amazonaws.com\n"
    "  [found] example.blob.core.windows.net\n"
    "[+] Done\n"
)


class CloudEnumKeywordTestCase(unittest.TestCase):
    def test_strips_tld_from_domain(self):
        self.assertEqual(_keyword_for("example.com"), "example")

    def test_uses_first_label_of_a_subdomain(self):
        self.assertEqual(_keyword_for("app.example.co.uk"), "app")


class CloudEnumParseTestCase(unittest.TestCase):
    def test_parses_found_buckets(self):
        module = CloudEnumModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(
            {a.value for a in assets},
            {"example.s3.amazonaws.com", "example.blob.core.windows.net"},
        )
        self.assertTrue(all(a.type == AssetType.BUCKET for a in assets))

    def test_lines_without_found_marker_are_ignored(self):
        module = CloudEnumModule()
        raw = "[+] Checking for AWS buckets\n[-] example.s3.amazonaws.com not found\n"
        self.assertEqual(module.parse(raw, target_raw="example.com"), [])

    def test_empty_output_returns_no_assets(self):
        module = CloudEnumModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

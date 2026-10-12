import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.cdncheck import CdncheckModule  # noqa: E402


class CdncheckParseTestCase(unittest.TestCase):
    def test_detects_cdn(self):
        module = CdncheckModule()
        raw = json.dumps({"host": "example.com", "cdn": True, "cdn_name": "cloudflare"})
        findings = module.parse(raw, target_raw="example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("CDN detected: cloudflare", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_no_cdn_waf_or_cloud_produces_no_findings(self):
        module = CdncheckModule()
        raw = json.dumps({"host": "example.com", "cdn": False, "waf": False, "cloud": False})
        self.assertEqual(module.parse(raw, target_raw="example.com"), [])

    def test_empty_output_returns_no_findings(self):
        module = CdncheckModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

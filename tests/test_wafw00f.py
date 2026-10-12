"""Tests for modules.vuln.wafw00f's parse() logic, using saved sample
JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.wafw00f import Wafw00fModule  # noqa: E402

SAMPLE_OUTPUT = """
[{"url": "https://example.com", "detected": true, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]
""".strip()

NONE_DETECTED = """
[{"url": "https://example.com", "detected": false, "firewall": "None", "manufacturer": "None"}]
""".strip()


class Wafw00fParseTestCase(unittest.TestCase):
    def test_parses_detected_waf_into_finding(self):
        module = Wafw00fModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("Cloudflare", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertTrue(findings[0].confirmed)

    def test_no_waf_detected_returns_no_findings(self):
        module = Wafw00fModule()
        findings = module.parse(NONE_DETECTED, target_raw="https://example.com")
        self.assertEqual(findings, [])

    def test_empty_output_returns_no_findings(self):
        module = Wafw00fModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = Wafw00fModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

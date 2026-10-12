"""Tests for modules.vuln.crlfuzz's parse() logic, using saved sample
plain-text output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.crlfuzz import CrlfuzzModule  # noqa: E402


class CrlfuzzParseTestCase(unittest.TestCase):
    def test_parses_plain_urls(self):
        module = CrlfuzzModule()
        raw = "https://example.com/a\nhttps://example.com/b"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 2)

    def test_strips_vuln_prefix(self):
        module = CrlfuzzModule()
        raw = "[VULN] https://example.com/a"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(findings[0].asset.value, "https://example.com/a")

    def test_findings_are_medium_and_confirmed(self):
        module = CrlfuzzModule()
        raw = "https://example.com/a"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertTrue(findings[0].confirmed)

    def test_non_url_lines_are_skipped(self):
        module = CrlfuzzModule()
        raw = "some banner text\nhttps://example.com/a"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)

    def test_empty_output_returns_no_findings(self):
        module = CrlfuzzModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

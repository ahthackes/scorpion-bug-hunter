"""Tests for modules.vuln.ssrfmap's parse() logic, using saved sample
console output instead of calling the real binary. Not auto-wired into
the Tier 2 chain (see the module's own docstring for why) -- this only
covers the module in isolation.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.ssrfmap import SsrfmapModule  # noqa: E402


class SsrfmapParseTestCase(unittest.TestCase):
    def test_parses_success_marker_lines(self):
        module = SsrfmapModule()
        raw = "[*] Starting module: readfiles\n[+] SSRF confirmed via interactsh callback\n[*] Done"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("SSRF confirmed", findings[0].description)

    def test_findings_are_high_and_unconfirmed(self):
        module = SsrfmapModule()
        raw = "[+] SSRF confirmed via interactsh callback"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertFalse(findings[0].confirmed)

    def test_lines_without_success_marker_are_ignored(self):
        module = SsrfmapModule()
        raw = "[*] Starting module: readfiles\n[-] No response"
        self.assertEqual(module.parse(raw, target_raw="https://example.com"), [])

    def test_empty_output_returns_no_findings(self):
        module = SsrfmapModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

"""Tests for modules.vuln.openredirex's parse() logic, using saved
sample plain-text output instead of calling the real binary, plus
run()'s guard-rails (FUZZ marker required, payload file must exist).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity, ToolError  # noqa: E402
from modules.vuln.openredirex import OpenRedireXModule  # noqa: E402


class OpenRedireXParseTestCase(unittest.TestCase):
    def test_parses_plain_urls(self):
        module = OpenRedireXModule()
        raw = "https://example.com/redirect?url=//evil.com"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)

    def test_findings_are_low_and_confirmed(self):
        module = OpenRedireXModule()
        raw = "https://example.com/redirect?url=//evil.com"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertTrue(findings[0].confirmed)

    def test_non_url_lines_are_skipped(self):
        module = OpenRedireXModule()
        raw = "scanning...\nhttps://example.com/redirect?url=//evil.com"
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)

    def test_empty_output_returns_no_findings(self):
        module = OpenRedireXModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_run_raises_tool_error_without_fuzz_marker(self):
        module = OpenRedireXModule()
        with self.assertRaises(ToolError):
            module.run("https://example.com/redirect?url=http://x", {})

    def test_run_raises_tool_error_when_payloads_missing(self):
        module = OpenRedireXModule()
        config = {"tiers": {"tier2": {"openredirex_payloads": "/no/such/payloads.txt"}}}
        with self.assertRaises(ToolError):
            module.run("https://example.com/redirect?url=FUZZ", config)


if __name__ == "__main__":
    unittest.main()

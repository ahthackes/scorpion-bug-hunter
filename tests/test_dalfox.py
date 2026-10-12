"""Tests for modules.vuln.dalfox's parse() logic, using saved sample
JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.dalfox import DalfoxModule  # noqa: E402

SAMPLE_OUTPUT = """
[
  {"type": "V", "param": "q", "payload": "<script>alert(1)</script>",
   "evidence": "reflected in body", "severity": "High"},
  {"type": "G", "param": "ref", "payload": "\\"><svg onload=alert(1)>",
   "evidence": "possible reflection", "severity": "Medium"}
]
""".strip()


class DalfoxParseTestCase(unittest.TestCase):
    def test_parses_all_entries_into_findings(self):
        module = DalfoxModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 2)

    def test_verified_type_is_confirmed(self):
        module = DalfoxModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        by_param = {f.description: f for f in findings}
        verified = [f for f in findings if "q" in f.title]
        self.assertTrue(verified[0].confirmed)

    def test_grep_type_is_unconfirmed(self):
        module = DalfoxModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        grep_finding = [f for f in findings if "ref" in f.title][0]
        self.assertFalse(grep_finding.confirmed)

    def test_severity_mapping(self):
        module = DalfoxModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        severities = {f.title: f.severity for f in findings}
        self.assertIn(Severity.HIGH, severities.values())
        self.assertIn(Severity.MEDIUM, severities.values())

    def test_empty_output_returns_no_findings(self):
        module = DalfoxModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = DalfoxModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])

    def test_single_object_is_wrapped_into_a_list(self):
        module = DalfoxModule()
        raw = '{"type": "V", "param": "x", "severity": "low"}'
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()

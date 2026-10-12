"""Tests for modules.vuln.nuclei's parse() logic, using saved sample
JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.nuclei import NucleiModule  # noqa: E402

SAMPLE_OUTPUT = """
[
  {
    "template-id": "exposed-panel",
    "info": {"name": "Exposed Admin Panel", "severity": "medium", "description": "Found an exposed panel"},
    "matched-at": "https://example.com/admin"
  },
  {
    "template-id": "tech-detect",
    "info": {"name": "Tech Detect", "severity": "info"},
    "matched-at": "https://example.com"
  }
]
""".strip()


class NucleiParseTestCase(unittest.TestCase):
    def test_parses_findings(self):
        module = NucleiModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 2)

    def test_severity_mapping(self):
        module = NucleiModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        severities = {f.title: f.severity for f in findings}
        self.assertEqual(severities["Exposed Admin Panel"], Severity.MEDIUM)
        self.assertEqual(severities["Tech Detect"], Severity.INFO)

    def test_findings_are_confirmed(self):
        module = NucleiModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertTrue(all(f.confirmed for f in findings))

    def test_unknown_severity_defaults_to_info(self):
        module = NucleiModule()
        raw = '[{"template-id": "x", "info": {"name": "X", "severity": "weird"}, "matched-at": "https://example.com"}]'
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_empty_output_returns_no_findings(self):
        module = NucleiModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = NucleiModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

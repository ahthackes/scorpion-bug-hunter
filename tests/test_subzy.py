"""Tests for modules.vuln.subzy's parse() logic, using saved sample JSON
output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.subzy import SubzyModule  # noqa: E402

SAMPLE_OUTPUT = """
[
  {"subdomain": "forgotten.example.com", "vulnerable": true, "service": "GitHub Pages"},
  {"subdomain": "ok.example.com", "vulnerable": false, "service": "AWS S3"}
]
""".strip()


class SubzyParseTestCase(unittest.TestCase):
    def test_only_vulnerable_entries_become_findings(self):
        module = SubzyModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("forgotten.example.com", findings[0].title)

    def test_findings_are_high_severity_and_confirmed(self):
        module = SubzyModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertTrue(findings[0].confirmed)

    def test_single_object_is_wrapped_into_a_list(self):
        module = SubzyModule()
        raw = '{"subdomain": "x.example.com", "vulnerable": true, "service": "Heroku"}'
        findings = module.parse(raw, target_raw="example.com")
        self.assertEqual(len(findings), 1)

    def test_empty_output_returns_no_findings(self):
        module = SubzyModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = SubzyModule()
        self.assertEqual(module.parse("not json", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

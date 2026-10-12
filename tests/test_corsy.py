"""Tests for modules.vuln.corsy's parse() logic, using saved sample JSON
output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.corsy import CorsyModule  # noqa: E402

SAMPLE_OUTPUT = """
{
  "https://example.com": {"vulnerable": true, "issues": ["Reflects Origin", "Null Origin Allowed"]},
  "https://example.com/safe": {"vulnerable": false, "issues": []}
}
""".strip()


class CorsyParseTestCase(unittest.TestCase):
    def test_only_vulnerable_entries_become_findings(self):
        module = CorsyModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 2)  # two issues under the one vulnerable URL

    def test_findings_are_medium_and_unconfirmed(self):
        module = CorsyModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        for finding in findings:
            self.assertEqual(finding.severity, Severity.MEDIUM)
            self.assertFalse(finding.confirmed)

    def test_titles_include_the_issue(self):
        module = CorsyModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        titles = [f.title for f in findings]
        self.assertTrue(any("Reflects Origin" in t for t in titles))
        self.assertTrue(any("Null Origin Allowed" in t for t in titles))

    def test_empty_output_returns_no_findings(self):
        module = CorsyModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = CorsyModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])

    def test_non_dict_top_level_returns_no_findings(self):
        module = CorsyModule()
        self.assertEqual(module.parse("[1, 2]", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

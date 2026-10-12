"""Tests for modules.vuln.wpscan's parse() logic, using saved sample
JSON output instead of calling the real binary. Not auto-wired into the
Tier 2 chain (see the module's own docstring for why) -- this only
covers the module in isolation.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.wpscan import WpscanModule  # noqa: E402

SAMPLE_OUTPUT = """
{
  "version": {"number": "5.8", "vulnerabilities": [
    {"title": "WordPress < 5.9 - Object Injection", "references": {"cve": ["2022-1234"]}}
  ]},
  "main_theme": {"slug": "twentytwenty", "vulnerabilities": []},
  "plugins": {
    "contact-form-7": {"vulnerabilities": [
      {"title": "Contact Form 7 < 5.5 - Unrestricted File Upload", "references": {}}
    ]}
  }
}
""".strip()


class WpscanParseTestCase(unittest.TestCase):
    def test_parses_core_plugin_and_theme_vulnerabilities(self):
        module = WpscanModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 2)  # one core, one plugin -- theme has none

    def test_cve_backed_finding_is_high_severity(self):
        module = WpscanModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        core_finding = [f for f in findings if "WordPress core" in f.title][0]
        self.assertEqual(core_finding.severity, Severity.HIGH)
        self.assertIn("CVE", core_finding.description)

    def test_finding_without_cve_is_medium_severity(self):
        module = WpscanModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        plugin_finding = [f for f in findings if "contact-form-7" in f.title][0]
        self.assertEqual(plugin_finding.severity, Severity.MEDIUM)

    def test_findings_are_confirmed(self):
        module = WpscanModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertTrue(all(f.confirmed for f in findings))

    def test_empty_output_returns_no_findings(self):
        module = WpscanModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = WpscanModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

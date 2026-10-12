import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.dnsreaper import DnsReaperModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps([
    {"domain": "old.example.com", "vulnerable": True, "signature_name": "github-pages", "confidence": "high"},
    {"domain": "fine.example.com", "vulnerable": False},
])


class DnsReaperParseTestCase(unittest.TestCase):
    def test_only_vulnerable_entries_become_findings(self):
        module = DnsReaperModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("old.example.com", findings[0].title)

    def test_findings_are_high_and_confirmed(self):
        module = DnsReaperModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(findings[0].severity.value, "high")
        self.assertTrue(findings[0].confirmed)

    def test_empty_output_returns_no_findings(self):
        module = DnsReaperModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

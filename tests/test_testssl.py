import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.testssl import TestsslModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps([
    {"id": "POODLE", "severity": "HIGH", "finding": "vulnerable to POODLE"},
    {"id": "TLS1", "severity": "OK", "finding": "TLS 1.2 offered"},
])


class TestsslParseTestCase(unittest.TestCase):
    def test_only_genuine_weaknesses_become_findings(self):
        module = TestsslModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("POODLE", findings[0].title)

    def test_ok_severity_is_not_a_finding(self):
        module = TestsslModule()
        raw = json.dumps([{"id": "TLS1", "severity": "OK", "finding": "fine"}])
        self.assertEqual(module.parse(raw, target_raw="https://example.com"), [])

    def test_empty_output_returns_no_findings(self):
        module = TestsslModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

"""Tests for modules.vuln.smuggler's parse() logic, using saved sample
JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.smuggler import SmugglerModule  # noqa: E402

SAMPLE_OUTPUT = """
[
  {"technique": "CL.TE", "vulnerable": true, "payload": "...", "confidence": "high"},
  {"technique": "TE.CL", "vulnerable": false}
]
""".strip()


class SmugglerParseTestCase(unittest.TestCase):
    def test_only_vulnerable_entries_become_findings(self):
        module = SmugglerModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("CL.TE", findings[0].title)

    def test_findings_are_high_and_confirmed(self):
        module = SmugglerModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertTrue(findings[0].confirmed)

    def test_single_object_is_wrapped_into_a_list(self):
        module = SmugglerModule()
        raw = '{"technique": "TE.TE", "vulnerable": true, "confidence": "medium"}'
        findings = module.parse(raw, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)

    def test_empty_output_returns_no_findings(self):
        module = SmugglerModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = SmugglerModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

"""Tests for modules.vuln.nuclei_full's parse() logic, using saved
sample JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import RiskTier, Severity  # noqa: E402
from modules.vuln.nuclei_full import NucleiFullModule  # noqa: E402

SAMPLE_OUTPUT = """
[
  {"template-id": "sqli-detect", "info": {"name": "SQL Injection", "severity": "critical"},
   "matched-at": "https://example.com/item?id=1"}
]
""".strip()


class NucleiFullParseTestCase(unittest.TestCase):
    def test_parses_findings(self):
        module = NucleiFullModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_findings_are_tagged_tier2(self):
        module = NucleiFullModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(findings[0].tier, RiskTier.TIER2_FUZZING)
        self.assertEqual(findings[0].tool_name, "nuclei-full")

    def test_findings_are_confirmed(self):
        module = NucleiFullModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertTrue(findings[0].confirmed)

    def test_empty_output_returns_no_findings(self):
        module = NucleiFullModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = NucleiFullModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

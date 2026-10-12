"""Tests for the secrets-scanning modules: trufflehog and gitleaks
parse() logic. Both produce Findings, not Assets -- a leaked secret is
the thing worth reporting, not a stepping stone to more recon.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.recon.gitleaks import GitleaksModule  # noqa: E402
from modules.recon.trufflehog import TrufflehogModule  # noqa: E402

TRUFFLEHOG_OUTPUT = "\n".join(
    [
        json.dumps({
            "DetectorName": "AWS", "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config.py"}}},
        }),
        json.dumps({
            "DetectorName": "Generic", "Verified": False,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "notes.txt"}}},
        }),
    ]
)

GITLEAKS_OUTPUT = json.dumps([
    {"RuleID": "aws-access-token", "File": "deploy.sh", "Commit": "abcdef1234567890"},
    {"RuleID": "generic-api-key", "File": "settings.py", "Commit": "0123456789abcdef"},
])


class TrufflehogParseTestCase(unittest.TestCase):
    def test_verified_critical_detector_is_critical_severity(self):
        module = TrufflehogModule()
        findings = module.parse(TRUFFLEHOG_OUTPUT, target_raw="https://github.com/acme/backend")
        aws_finding = next(f for f in findings if "AWS" in f.title)
        self.assertEqual(aws_finding.severity, Severity.CRITICAL)
        self.assertTrue(aws_finding.confirmed)

    def test_unverified_generic_detector_is_lower_severity_and_unconfirmed(self):
        module = TrufflehogModule()
        findings = module.parse(TRUFFLEHOG_OUTPUT, target_raw="https://github.com/acme/backend")
        generic_finding = next(f for f in findings if "Generic" in f.title)
        self.assertEqual(generic_finding.severity, Severity.MEDIUM)
        self.assertFalse(generic_finding.confirmed)

    def test_empty_output(self):
        module = TrufflehogModule()
        self.assertEqual(module.parse("", target_raw="https://github.com/acme/backend"), [])


class GitleaksParseTestCase(unittest.TestCase):
    def test_parses_findings_with_known_rule_severity(self):
        module = GitleaksModule()
        findings = module.parse(GITLEAKS_OUTPUT, target_raw="/tmp/acme-backend")
        self.assertEqual(len(findings), 2)
        aws_finding = next(f for f in findings if "aws-access-token" in f.title)
        self.assertEqual(aws_finding.severity, Severity.CRITICAL)

    def test_findings_start_unconfirmed(self):
        module = GitleaksModule()
        findings = module.parse(GITLEAKS_OUTPUT, target_raw="/tmp/acme-backend")
        self.assertTrue(all(not f.confirmed for f in findings))

    def test_empty_report_is_empty_list(self):
        module = GitleaksModule()
        self.assertEqual(module.parse("[]", target_raw="/tmp/acme-backend"), [])
        self.assertEqual(module.parse("", target_raw="/tmp/acme-backend"), [])


if __name__ == "__main__":
    unittest.main()

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.vuln.s3scanner import S3ScannerModule  # noqa: E402


class S3ScannerParseTestCase(unittest.TestCase):
    def test_publicly_readable_bucket_is_high(self):
        module = S3ScannerModule()
        raw = json.dumps({"name": "example", "exists": True,
                           "permission_allusers_read": "allowed", "permission_allusers_write": "denied"})
        findings = module.parse(raw, target_raw="example.s3.amazonaws.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_publicly_writable_bucket_is_critical(self):
        module = S3ScannerModule()
        raw = json.dumps({"name": "example", "exists": True,
                           "permission_allusers_read": "denied", "permission_allusers_write": "allowed"})
        findings = module.parse(raw, target_raw="example.s3.amazonaws.com")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_nonexistent_bucket_produces_no_finding(self):
        module = S3ScannerModule()
        raw = json.dumps({"name": "example", "exists": False})
        self.assertEqual(module.parse(raw, target_raw="example.s3.amazonaws.com"), [])

    def test_private_bucket_produces_no_finding(self):
        module = S3ScannerModule()
        raw = json.dumps({"name": "example", "exists": True,
                           "permission_allusers_read": "denied", "permission_allusers_write": "denied"})
        self.assertEqual(module.parse(raw, target_raw="example.s3.amazonaws.com"), [])


if __name__ == "__main__":
    unittest.main()

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.recon.tlsx import TlsxModule, TlsxPostureModule  # noqa: E402

PASSIVE_OUTPUT = "www.example.com\n*.example.com\napi.example.com\n"

POSTURE_OUTPUT = json.dumps({
    "host": "example.com", "expired": True, "deprecated_tls": True,
    "weak_cipher": False, "not_after": "2020-01-01T00:00:00Z",
})


class TlsxPassiveTestCase(unittest.TestCase):
    def test_parses_sans_and_strips_wildcard_prefix(self):
        module = TlsxModule()
        assets = module.parse(PASSIVE_OUTPUT, target_raw="example.com")
        self.assertEqual({a.value for a in assets}, {"www.example.com", "example.com", "api.example.com"})

    def test_empty_output_returns_no_assets(self):
        module = TlsxModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


class TlsxPostureTestCase(unittest.TestCase):
    def test_expired_and_deprecated_tls_produce_separate_findings(self):
        module = TlsxPostureModule()
        findings = module.parse(POSTURE_OUTPUT, target_raw="example.com")
        titles = {f.title for f in findings}
        self.assertIn("Expired TLS certificate", titles)
        self.assertIn("Deprecated TLS protocol accepted", titles)
        self.assertEqual(len(findings), 2)  # weak_cipher is False -- no third finding

    def test_findings_are_confirmed_medium_or_lower(self):
        module = TlsxPostureModule()
        findings = module.parse(POSTURE_OUTPUT, target_raw="example.com")
        self.assertTrue(all(f.confirmed for f in findings))
        self.assertTrue(all(f.severity in (Severity.MEDIUM, Severity.LOW) for f in findings))

    def test_clean_cert_produces_no_findings(self):
        module = TlsxPostureModule()
        clean = json.dumps({"host": "example.com", "expired": False, "deprecated_tls": False, "weak_cipher": False})
        self.assertEqual(module.parse(clean, target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

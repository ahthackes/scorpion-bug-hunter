import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.dnstwist import DnstwistModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps([
    {"fuzzer": "homoglyph", "domain-name": "examp1e.com", "dns-a": ["1.2.3.4"]},
    {"fuzzer": "addition", "domain-name": "example1.com"},  # not registered -- no dns-a/dns-aaaa
    {"fuzzer": "original", "domain-name": "example.com", "dns-a": ["5.6.7.8"]},  # the target itself
])


class DnstwistParseTestCase(unittest.TestCase):
    def test_only_registered_lookalikes_become_findings(self):
        module = DnstwistModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("examp1e.com", findings[0].title)

    def test_the_target_itself_is_excluded(self):
        module = DnstwistModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertNotIn("example.com -- registered", str(findings))

    def test_empty_output_returns_no_findings(self):
        module = DnstwistModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_json_returns_no_findings(self):
        module = DnstwistModule()
        self.assertEqual(module.parse("not json", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()

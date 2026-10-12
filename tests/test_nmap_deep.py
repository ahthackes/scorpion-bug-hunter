"""Tests for modules.recon.nmap_deep's parse() logic (nmap XML output),
using saved sample output instead of calling the real binary, plus
run()'s "no ports given" short-circuit.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import Severity  # noqa: E402
from modules.recon.nmap_deep import NmapDeepModule  # noqa: E402

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapDeepParseTestCase(unittest.TestCase):
    def test_parses_open_ports_into_findings(self):
        module = NmapDeepModule()
        findings = module.parse(SAMPLE_XML, target_raw="example.com")
        self.assertEqual(len(findings), 2)

    def test_skips_ports_without_a_service_element(self):
        module = NmapDeepModule()
        findings = module.parse(SAMPLE_XML, target_raw="example.com")
        titles = [f.title for f in findings]
        self.assertTrue(any("80" in t for t in titles))
        self.assertTrue(any("443" in t for t in titles))
        self.assertFalse(any("21" in t for t in titles))

    def test_findings_are_info_and_confirmed(self):
        module = NmapDeepModule()
        findings = module.parse(SAMPLE_XML, target_raw="example.com")
        for finding in findings:
            self.assertEqual(finding.severity, Severity.INFO)
            self.assertTrue(finding.confirmed)
            self.assertEqual(finding.tool_name, "nmap")

    def test_empty_output_returns_no_findings(self):
        module = NmapDeepModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_malformed_xml_returns_no_findings(self):
        module = NmapDeepModule()
        self.assertEqual(module.parse("<not><valid", target_raw="example.com"), [])

    def test_run_with_no_ports_returns_empty_without_calling_nmap(self):
        module = NmapDeepModule()
        self.assertEqual(module.run("1.2.3.4", {}, ports=[]), "")


if __name__ == "__main__":
    unittest.main()

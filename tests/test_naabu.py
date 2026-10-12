"""Tests for modules.recon.naabu's parse() logic, using saved sample
output instead of calling the real binary, plus run()'s handling of a
host with no DNS record (a real case hit during manual testing against
dead subdomains like autodiscover./cpanel. -- see the module docstring).
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.naabu import NaabuModule  # noqa: E402

SAMPLE_OUTPUT = """
{"host": "app.example.com", "ip": "1.2.3.4", "port": 443}
{"host": "app.example.com", "ip": "1.2.3.4", "port": 80}
{"host": "app.example.com", "ip": "1.2.3.4", "port": 443}
""".strip()


class NaabuParseTestCase(unittest.TestCase):
    def test_parses_jsonlines_into_ip_assets(self):
        module = NaabuModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["app.example.com:443", "app.example.com:80"])

    def test_dedupes_repeated_host_port_pairs(self):
        module = NaabuModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)  # :443 appears twice in the sample

    def test_asset_type_and_meta_are_set(self):
        module = NaabuModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.IP)
            self.assertEqual(asset.discovered_by, "naabu")
            self.assertIn("port", asset.meta)

    def test_no_open_ports_returns_empty_list(self):
        module = NaabuModule()
        assets = module.parse("", target_raw="example.com")
        self.assertEqual(assets, [])


class NaabuRunNoDnsRecordTestCase(unittest.TestCase):
    """A subdomain with no A/AAAA record (dead autodiscover./cpanel.
    artifacts from passive recon) makes naabu exit non-zero with this
    stderr message -- run() must treat it as a clean empty result, not
    raise, since it's an expected outcome, not a tool failure.
    """

    def test_no_dns_record_returns_empty_string_not_raise(self):
        fake_result = subprocess.CompletedProcess(
            args=["naabu"], returncode=1, stdout="",
            stderr="[FTL] Could not run enumeration: no valid ipv4 or ipv6 targets were found",
        )
        with mock.patch("modules.recon.naabu.run_command", return_value=fake_result):
            module = NaabuModule()
            raw = module.run("autodiscover.example.com", {"timeouts": {}})
        self.assertEqual(raw, "")

    def test_genuine_tool_failure_still_raises(self):
        fake_result = subprocess.CompletedProcess(
            args=["naabu"], returncode=1, stdout="", stderr="panic: something actually broke",
        )
        with mock.patch("modules.recon.naabu.run_command", return_value=fake_result):
            module = NaabuModule()
            with self.assertRaises(RuntimeError):
                module.run("example.com", {"timeouts": {}})


if __name__ == "__main__":
    unittest.main()

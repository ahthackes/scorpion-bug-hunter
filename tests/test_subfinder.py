"""Tests for modules.recon.subfinder's parse() logic, using saved sample
output instead of calling the real binary (which isn't installed in CI/dev
sandboxes). The run() method itself is exercised in test_modules_base.py's
ToolNotInstalled coverage via the shared run_command() path.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.subfinder import SubfinderModule  # noqa: E402

SAMPLE_OUTPUT = """
{"host": "www.example.com", "input": "example.com", "source": "crtsh"}
{"host": "api.example.com", "input": "example.com", "source": "virustotal"}
{"host": "www.example.com", "input": "example.com", "source": "alienvault"}
""".strip()


class SubfinderParseTestCase(unittest.TestCase):
    def test_parses_jsonlines_into_assets(self):
        module = SubfinderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["api.example.com", "www.example.com"])

    def test_dedupes_repeated_hosts_from_multiple_sources(self):
        module = SubfinderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)  # www.example.com appears twice in the sample

    def test_asset_type_and_target_raw_are_set(self):
        module = SubfinderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.SUBDOMAIN)
            self.assertEqual(asset.target_raw, "example.com")
            self.assertTrue(asset.discovered_by.startswith("subfinder:"))

    def test_ignores_blank_and_malformed_lines(self):
        module = SubfinderModule()
        messy = SAMPLE_OUTPUT + "\n\n\nnot json at all\n"
        assets = module.parse(messy, target_raw="example.com")
        self.assertEqual(len(assets), 2)


if __name__ == "__main__":
    unittest.main()

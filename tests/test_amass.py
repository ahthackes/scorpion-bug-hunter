import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.amass import AmassModule  # noqa: E402

SAMPLE_OUTPUT = "www.example.com\napi.example.com\nwww.example.com\n"


class AmassParseTestCase(unittest.TestCase):
    def test_parses_and_dedupes_hostnames(self):
        module = AmassModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual({a.value for a in assets}, {"www.example.com", "api.example.com"})

    def test_empty_output_returns_no_assets(self):
        module = AmassModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_discovered_by_is_amass(self):
        module = AmassModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertTrue(all(a.discovered_by == "amass" for a in assets))


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.shuffledns import ShuffledNSModule  # noqa: E402

SAMPLE_OUTPUT = "app.example.com\napi.example.com\n"


class ShuffledNSParseTestCase(unittest.TestCase):
    def test_parses_resolved_hosts(self):
        module = ShuffledNSModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual({a.value for a in assets}, {"app.example.com", "api.example.com"})

    def test_empty_output_returns_no_assets(self):
        module = ShuffledNSModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])

    def test_run_with_no_candidate_hosts_returns_empty_string(self):
        module = ShuffledNSModule()
        self.assertEqual(module.run("", {}), "")


if __name__ == "__main__":
    unittest.main()

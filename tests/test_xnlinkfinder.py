import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.xnlinkfinder import XnLinkFinderModule  # noqa: E402

SAMPLE_OUTPUT = "/api/v1/users\nhttps://example.com/api/v1/orders\n"


class XnLinkFinderParseTestCase(unittest.TestCase):
    def test_resolves_bare_paths_against_target(self):
        module = XnLinkFinderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertIn("https://example.com/api/v1/users", {a.value for a in assets})

    def test_absolute_urls_are_kept_as_is(self):
        module = XnLinkFinderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertIn("https://example.com/api/v1/orders", {a.value for a in assets})

    def test_empty_output_returns_no_assets(self):
        module = XnLinkFinderModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

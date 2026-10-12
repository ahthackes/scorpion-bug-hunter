"""Tests for modules.recon.gowitness's parse() logic, using a real
temp directory with a fake screenshot file instead of calling the real
binary.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.gowitness import GowitnessModule  # noqa: E402


class GowitnessParseTestCase(unittest.TestCase):
    def test_finds_screenshot_in_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "shot.png").write_bytes(b"\x89PNG\r\n")
            module = GowitnessModule()
            assets = module.parse(tmp, target_raw="https://example.com")
            self.assertEqual(len(assets), 1)
            self.assertEqual(assets[0].value, "https://example.com")
            self.assertTrue(assets[0].meta["screenshot_path"].endswith("shot.png"))

    def test_empty_directory_returns_no_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = GowitnessModule()
            assets = module.parse(tmp, target_raw="https://example.com")
            self.assertEqual(assets, [])

    def test_nonexistent_directory_returns_no_assets(self):
        module = GowitnessModule()
        assets = module.parse("/no/such/dir", target_raw="https://example.com")
        self.assertEqual(assets, [])

    def test_empty_raw_output_returns_no_assets(self):
        module = GowitnessModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

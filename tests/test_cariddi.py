import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.cariddi import CariddiModule  # noqa: E402

SAMPLE_OUTPUT = "\n".join([
    json.dumps({"url": "https://example.com/api/v1/users"}),
    json.dumps({"url": "https://example.com/api/v1/users"}),
])


class CariddiParseTestCase(unittest.TestCase):
    def test_parses_and_dedupes_urls(self):
        module = CariddiModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].value, "https://example.com/api/v1/users")

    def test_empty_output_returns_no_assets(self):
        module = CariddiModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

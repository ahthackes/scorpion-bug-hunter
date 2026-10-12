import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.gospider import GospiderModule  # noqa: E402

SAMPLE_OUTPUT = "\n".join([
    json.dumps({"output": "https://example.com/page1"}),
    json.dumps({"output": "https://example.com/page2"}),
    "not json -- ignored",
])


class GospiderParseTestCase(unittest.TestCase):
    def test_parses_crawled_urls(self):
        module = GospiderModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual({a.value for a in assets}, {"https://example.com/page1", "https://example.com/page2"})

    def test_empty_output_returns_no_assets(self):
        module = GospiderModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

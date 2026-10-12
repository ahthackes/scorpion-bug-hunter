"""Tests for modules.recon.httpx_probe's parse() logic, using saved sample
output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.httpx_probe import HttpxModule  # noqa: E402

SAMPLE_OUTPUT = """
{"url": "https://app.example.com", "status_code": 200, "title": "App", "tech": ["nginx", "React"], "webserver": "nginx", "host": "1.2.3.4"}
{"url": "https://api.example.com", "status_code": 401, "title": "", "tech": ["Kong"], "webserver": "Kong", "host": "1.2.3.5"}
""".strip()


class HttpxParseTestCase(unittest.TestCase):
    def test_parses_jsonlines_into_url_assets(self):
        module = HttpxModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["https://api.example.com", "https://app.example.com"])

    def test_asset_type_and_meta_are_set(self):
        module = HttpxModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        app = next(a for a in assets if "app." in a.value)
        self.assertEqual(app.type, AssetType.URL)
        self.assertEqual(app.meta["status_code"], 200)
        self.assertEqual(app.meta["tech"], ["nginx", "React"])
        self.assertEqual(app.discovered_by, "httpx")

    def test_ignores_rows_with_no_url(self):
        messy = SAMPLE_OUTPUT + '\n{"status_code": 500}\n'
        module = HttpxModule()
        assets = module.parse(messy, target_raw="example.com")
        self.assertEqual(len(assets), 2)

    def test_empty_output_means_dead_host(self):
        module = HttpxModule()
        assets = module.parse("", target_raw="example.com")
        self.assertEqual(assets, [])


if __name__ == "__main__":
    unittest.main()

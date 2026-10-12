import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.whatweb import WhatwebModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps([
    {"target": "https://example.com", "plugins": {"nginx": {}, "WordPress": {}}}
])


class WhatwebParseTestCase(unittest.TestCase):
    def test_parses_detected_tech(self):
        module = WhatwebModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].meta["tech"], ["WordPress", "nginx"])

    def test_empty_plugins_returns_no_assets(self):
        module = WhatwebModule()
        raw = json.dumps([{"target": "https://example.com", "plugins": {}}])
        self.assertEqual(module.parse(raw, target_raw="https://example.com"), [])

    def test_empty_output_returns_no_assets(self):
        module = WhatwebModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_assets(self):
        module = WhatwebModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()

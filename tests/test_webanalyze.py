"""Tests for modules.vuln.webanalyze's parse() logic, using saved sample
JSON output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.webanalyze import WebanalyzeModule  # noqa: E402

SAMPLE_OUTPUT = """
{"hostname": "https://example.com", "matches": [{"app": "nginx"}, {"app": "PHP"}]}
""".strip()


class WebanalyzeParseTestCase(unittest.TestCase):
    def test_parses_tech_matches(self):
        module = WebanalyzeModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(len(assets), 1)
        self.assertEqual(sorted(assets[0].meta["tech"]), ["PHP", "nginx"])

    def test_no_matches_returns_no_assets(self):
        module = WebanalyzeModule()
        raw = '{"hostname": "https://example.com", "matches": []}'
        self.assertEqual(module.parse(raw, target_raw="https://example.com"), [])

    def test_empty_output_returns_no_assets(self):
        module = WebanalyzeModule()
        self.assertEqual(module.parse("", target_raw="https://example.com"), [])

    def test_malformed_json_returns_no_assets(self):
        module = WebanalyzeModule()
        self.assertEqual(module.parse("not json", target_raw="https://example.com"), [])

    def test_discovered_by_is_set(self):
        module = WebanalyzeModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com")
        self.assertEqual(assets[0].discovered_by, "webanalyze")


if __name__ == "__main__":
    unittest.main()

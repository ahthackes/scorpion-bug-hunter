"""Tests for modules.recon.jsluice's parse()/parse_secrets() logic, using
saved sample output instead of calling the real binary.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.jsluice import JsluiceModule  # noqa: E402

URLS_OUTPUT = """
{"url": "/api/v1/users", "method": "GET"}
{"url": "/api/v1/admin", "method": "POST"}
{"url": "/api/v1/users", "method": "GET"}
""".strip()

SECRETS_OUTPUT = """
{"kind": "aws-key", "severity": "high"}
{"kind": "generic-api-key", "severity": "low"}
""".strip()


class JsluiceParseUrlsTestCase(unittest.TestCase):
    def test_parses_urls_into_endpoint_assets(self):
        module = JsluiceModule()
        assets = module.parse(URLS_OUTPUT, target_raw="app.js")
        values = sorted(a.value for a in assets)
        self.assertEqual(values, ["/api/v1/admin", "/api/v1/users"])

    def test_dedupes_repeated_urls(self):
        module = JsluiceModule()
        assets = module.parse(URLS_OUTPUT, target_raw="app.js")
        self.assertEqual(len(assets), 2)

    def test_asset_type_and_meta(self):
        module = JsluiceModule()
        assets = module.parse(URLS_OUTPUT, target_raw="app.js")
        for asset in assets:
            self.assertEqual(asset.type, AssetType.ENDPOINT)
            self.assertIn("method", asset.meta)

    def test_empty_output_returns_no_assets(self):
        module = JsluiceModule()
        self.assertEqual(module.parse("", target_raw="app.js"), [])


class JsluiceParseSecretsTestCase(unittest.TestCase):
    def test_parses_secrets_into_unconfirmed_findings(self):
        module = JsluiceModule()
        findings = module.parse_secrets(SECRETS_OUTPUT, target_raw="app.js")
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertFalse(finding.confirmed)

    def test_empty_output_returns_no_findings(self):
        module = JsluiceModule()
        self.assertEqual(module.parse_secrets("", target_raw="app.js"), [])


if __name__ == "__main__":
    unittest.main()

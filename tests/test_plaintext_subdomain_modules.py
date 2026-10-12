"""
Tests for the plain-text-output subdomain-enum modules: assetfinder,
github-subdomains, gitlab-subdomains, chaos, cero. They all share the same
"one hostname per line" output shape, so these tests are parametrized
across all five rather than duplicated per file.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import AssetType  # noqa: E402
from modules.recon.assetfinder import AssetfinderModule  # noqa: E402
from modules.recon.cero import CeroModule  # noqa: E402
from modules.recon.chaos import ChaosModule  # noqa: E402
from modules.recon.github_subdomains import GithubSubdomainsModule  # noqa: E402
from modules.recon.gitlab_subdomains import GitlabSubdomainsModule  # noqa: E402

SAMPLE_OUTPUT = "www.example.com\napi.example.com\nwww.example.com\n\n"

MODULES = [
    (AssetfinderModule, "assetfinder"),
    (GithubSubdomainsModule, "github-subdomains"),
    (GitlabSubdomainsModule, "gitlab-subdomains"),
    (ChaosModule, "chaos"),
]


class PlaintextSubdomainModulesTestCase(unittest.TestCase):
    def test_all_modules_parse_and_dedupe_plaintext_output(self):
        for module_cls, expected_source in MODULES:
            with self.subTest(module=expected_source):
                module = module_cls()
                assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
                values = sorted(a.value for a in assets)
                self.assertEqual(values, ["api.example.com", "www.example.com"])
                self.assertTrue(all(a.type == AssetType.SUBDOMAIN for a in assets))
                self.assertTrue(all(a.discovered_by == expected_source for a in assets))

    def test_all_modules_handle_empty_output(self):
        for module_cls, _ in MODULES:
            module = module_cls()
            self.assertEqual(module.parse("", target_raw="example.com"), [])


class CeroModuleTestCase(unittest.TestCase):
    """cero gets its own test class -- it tags wildcard entries, which the
    plain-text modules above don't do."""

    def test_parses_and_dedupes(self):
        module = CeroModule()
        assets = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(assets), 2)

    def test_tags_wildcard_entries(self):
        module = CeroModule()
        assets = module.parse("*.example.com\napp.example.com\n", target_raw="example.com")
        wildcard = next(a for a in assets if a.value == "*.example.com")
        concrete = next(a for a in assets if a.value == "app.example.com")
        self.assertTrue(wildcard.meta["wildcard"])
        self.assertFalse(concrete.meta["wildcard"])


if __name__ == "__main__":
    unittest.main()

"""
Tests for modules whose run() needs an API token/key from the environment
(github-subdomains, gitlab-subdomains, chaos, bbscope) -- verifies a
missing token/key raises ToolError (a clean, loggable skip) rather than
crashing or silently doing nothing.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import ToolError  # noqa: E402
from modules.recon.bbscope import BbscopeModule  # noqa: E402
from modules.recon.chaos import ChaosModule  # noqa: E402
from modules.recon.github_subdomains import GithubSubdomainsModule  # noqa: E402
from modules.recon.gitlab_subdomains import GitlabSubdomainsModule  # noqa: E402

CONFIG = {"timeouts": {"tool_default_seconds": 5}}


class TokenGatedModulesTestCase(unittest.TestCase):
    def test_github_subdomains_raises_without_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ToolError):
                GithubSubdomainsModule().run("example.com", CONFIG)

    def test_gitlab_subdomains_raises_without_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ToolError):
                GitlabSubdomainsModule().run("example.com", CONFIG)

    def test_chaos_raises_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ToolError):
                ChaosModule().run("example.com", CONFIG)

    def test_bbscope_raises_on_unknown_platform(self):
        config = {**CONFIG, "scope": {"platform": "not-a-real-platform"}}
        with self.assertRaises(ToolError):
            BbscopeModule().run("acme-corp", config)

    def test_bbscope_raises_without_token(self):
        config = {**CONFIG, "scope": {"platform": "h1"}}
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ToolError):
                BbscopeModule().run("acme-corp", config)


if __name__ == "__main__":
    unittest.main()

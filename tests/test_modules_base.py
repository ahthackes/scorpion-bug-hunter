"""Tests for modules.base -- the ToolModule interface contract and the
shared run_command() helper's "tool not installed" handling.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import (  # noqa: E402
    Asset,
    AssetType,
    RiskTier,
    ToolModule,
    ToolNotInstalled,
    run_command,
)


class RunCommandTestCase(unittest.TestCase):
    def test_missing_binary_raises_tool_not_installed(self):
        with self.assertRaises(ToolNotInstalled):
            run_command(["definitely-not-a-real-binary-xyz"])

    def test_existing_binary_runs(self):
        result = run_command(["echo", "hello"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_timeout_raises_tool_error(self):
        from modules.base import ToolError
        with self.assertRaises(ToolError):
            run_command(["sleep", "2"], timeout=1)


class AssetTestCase(unittest.TestCase):
    def test_equality_and_hash_by_type_and_value(self):
        a1 = Asset(type=AssetType.SUBDOMAIN, value="app.example.com", target_raw="example.com")
        a2 = Asset(type=AssetType.SUBDOMAIN, value="app.example.com", target_raw="different-source.com")
        a3 = Asset(type=AssetType.DOMAIN, value="app.example.com", target_raw="example.com")
        self.assertEqual(a1, a2)  # same type+value, different provenance -> still equal
        self.assertNotEqual(a1, a3)  # different type -> not equal
        self.assertEqual(len({a1, a2, a3}), 2)  # dedupes a1/a2 in a set


class ToolModuleTestCase(unittest.TestCase):
    def test_tool_module_is_abstract(self):
        with self.assertRaises(TypeError):
            ToolModule()  # can't instantiate directly -- run()/parse() unimplemented

    def test_concrete_subclass_must_implement_both_methods(self):
        class Incomplete(ToolModule):
            name = "incomplete"
            tier = RiskTier.TIER0_PASSIVE
            requires = AssetType.DOMAIN

            def run(self, target, config):
                return ""

        with self.assertRaises(TypeError):
            Incomplete()  # parse() still missing


if __name__ == "__main__":
    unittest.main()

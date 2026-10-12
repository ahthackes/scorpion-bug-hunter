"""Tests for core.scope_guard -- the safety boundary, so it gets tests
before any tool wrapper does. Pure stdlib (unittest) -- no pytest
dependency, so this runs anywhere Python 3 does.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from core.scope_guard import ScopeGuard, ScopeViolation  # noqa: E402


class ScopeGuardTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.scope_dir = self.tmp_path / "scope"
        self.scope_dir.mkdir()
        self.rules_path = self.tmp_path / "scope_rules.yaml"
        self.rules_path.write_text(
            yaml.dump(
                {
                    "defaults": {
                        "always_exclude": ["*.gov", "*.mil"],
                        "max_tier_without_override": 2,
                        "wildcard_matching": "strict",
                    }
                }
            )
        )

    def tearDown(self):
        self._tmp.cleanup()

    def write_program(self, name: str, **kwargs):
        data = {"program": name, "in_scope": [], "out_of_scope": [], "max_tier": 2}
        data.update(kwargs)
        (self.scope_dir / f"{name}.json").write_text(json.dumps(data))

    def guard(self) -> ScopeGuard:
        return ScopeGuard(scope_dir=str(self.scope_dir), global_rules_path=str(self.rules_path))

    def test_implicit_scope_allows_tier1_from_targets_txt(self):
        g = self.guard()
        self.assertTrue(g.is_allowed("app.example.com", tier=1, raw_target="example.com"))

    def test_implicit_scope_denies_tier3(self):
        g = self.guard()
        self.assertFalse(g.is_allowed("app.example.com", tier=3, raw_target="example.com"))

    def test_explicit_program_allows_tier3_when_set(self):
        self.write_program("acme", in_scope=["*.example.com", "example.com"], max_tier=3)
        g = self.guard()
        self.assertTrue(g.is_allowed("app.example.com", tier=3))

    def test_out_of_scope_denies_even_within_program(self):
        self.write_program(
            "acme", in_scope=["*.example.com"], out_of_scope=["blog.example.com"], max_tier=2,
        )
        g = self.guard()
        self.assertFalse(g.is_allowed("blog.example.com", tier=1))
        self.assertTrue(g.is_allowed("app.example.com", tier=1))

    def test_always_exclude_overrides_everything(self):
        self.write_program("acme", in_scope=["*.example.gov"], max_tier=3)
        g = self.guard()
        self.assertFalse(g.is_allowed("portal.example.gov", tier=0))

    def test_asset_outside_any_scope_is_denied(self):
        self.write_program("acme", in_scope=["*.example.com"], max_tier=2)
        g = self.guard()
        self.assertFalse(g.is_allowed("totally-unrelated.org", tier=0, raw_target="example.com"))

    def test_assert_allowed_raises_scope_violation(self):
        g = self.guard()
        with self.assertRaises(ScopeViolation):
            g.assert_allowed("app.example.com", tier=3, raw_target="example.com")


class ScopeGuardEnforceDisabledTestCase(unittest.TestCase):
    """enforce=False is the TESTING kill switch (config.scope.enforce in
    config/settings.yaml) -- everything is allowed at every tier, no
    scope file or always_exclude rule is consulted.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmp.name)
        # deliberately point at directories that don't exist -- enforce=False
        # must never try to load them
        self.guard = ScopeGuard(
            scope_dir=str(tmp_path / "does-not-exist"),
            global_rules_path=str(tmp_path / "does-not-exist.yaml"),
            enforce=False,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_any_host_allowed_at_tier0(self):
        self.assertTrue(self.guard.is_allowed("anything.whatsoever.org", tier=0))

    def test_any_host_allowed_at_tier3(self):
        self.assertTrue(self.guard.is_allowed("anything.whatsoever.org", tier=3))

    def test_always_exclude_patterns_are_not_enforced(self):
        self.assertTrue(self.guard.is_allowed("portal.example.gov", tier=1))

    def test_assert_allowed_never_raises(self):
        try:
            self.guard.assert_allowed("anything.whatsoever.org", tier=3)
        except ScopeViolation:
            self.fail("assert_allowed raised ScopeViolation with enforce=False")


if __name__ == "__main__":
    unittest.main()

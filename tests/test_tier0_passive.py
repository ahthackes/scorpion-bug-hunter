"""Integration tests for core.pipeline.tier0_passive -- the multi-source
merge, scope filtering, and graceful degradation when every external tool
is missing (true in this sandbox, and also true for anyone who hasn't
installed the full tool chain yet).
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from core.evidence_store import EvidenceStore  # noqa: E402
from core.pipeline import tier0_passive  # noqa: E402
from core.scope_guard import ScopeGuard  # noqa: E402
from db.models import Database  # noqa: E402

CONFIG = {"timeouts": {"tool_default_seconds": 5}}


class Tier0PassiveTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmp.name)
        self.db = Database(path=str(tmp_path / "test.sqlite"))

        scope_dir = tmp_path / "scope"
        scope_dir.mkdir()
        rules_path = tmp_path / "scope_rules.yaml"
        rules_path.write_text(yaml.dump({"defaults": {"always_exclude": [], "max_tier_without_override": 2}}))
        self.guard = ScopeGuard(scope_dir=str(scope_dir), global_rules_path=str(rules_path))

        self.evidence = EvidenceStore(base_dir=str(tmp_path / "output"), target_raw="example.com")

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()

    def test_falls_back_to_root_domain_when_every_source_is_unavailable(self):
        target = self.db.get_or_create_target("example.com")
        assets = tier0_passive.run("example.com", target.id, self.guard, self.db, CONFIG, self.evidence)

        # None of subfinder/assetfinder/github-subdomains/etc are installed
        # (or have tokens) in this sandbox -- Tier 0 should still return the
        # root domain itself rather than an empty list or a crash.
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].value, "example.com")

    def test_records_a_scan_row_per_source(self):
        target = self.db.get_or_create_target("example.com")
        tier0_passive.run("example.com", target.id, self.guard, self.db, CONFIG, self.evidence)

        with self.db.cursor() as cur:
            cur.execute("SELECT DISTINCT tool_name FROM scans WHERE target_id = ?", (target.id,))
            tool_names = {r["tool_name"] for r in cur.fetchall()}

        for expected in ("subfinder", "assetfinder", "github-subdomains",
                          "gitlab-subdomains", "chaos", "cero", "gau",
                          "amass", "tlsx", "asnmap", "cloud-enum", "gitdorker"):
            self.assertIn(expected, tool_names)

    def test_out_of_scope_root_domain_is_dropped(self):
        # always_exclude covers the whole TLD here to simulate a denied root
        rules_path = Path(self.guard.global_rules_path)
        rules_path.write_text(yaml.dump({"defaults": {"always_exclude": ["*.example.com", "example.com"],
                                                        "max_tier_without_override": 2}}))
        guard = ScopeGuard(scope_dir=str(self.guard.scope_dir), global_rules_path=str(rules_path))
        target = self.db.get_or_create_target("example.com")
        assets = tier0_passive.run("example.com", target.id, guard, self.db, CONFIG, self.evidence)
        self.assertEqual(assets, [])

    def test_every_source_gets_a_step_record_even_when_skipped(self):
        target = self.db.get_or_create_target("example.com")
        tier0_passive.run("example.com", target.id, self.guard, self.db, CONFIG, self.evidence)

        steps_log = (self.evidence.root / "steps.log").read_text()
        for expected in ("subfinder", "assetfinder", "github-subdomains",
                          "gitlab-subdomains", "chaos", "cero", "gau",
                          "amass", "tlsx", "asnmap", "cloud-enum", "gitdorker"):
            self.assertIn(expected, steps_log)


if __name__ == "__main__":
    unittest.main()

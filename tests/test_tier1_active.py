"""Integration tests for core.pipeline.tier1_active. Since httpx/naabu
aren't installed in this environment, these exercise the graceful-
degradation path (ToolNotInstalled) and the scope-violation path --
the two behaviors that matter most for this stage's safety contract.
Tool-specific parsing is covered in test_httpx_probe.py / test_naabu.py.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from core.evidence_store import EvidenceStore  # noqa: E402
from core.pipeline import tier1_active  # noqa: E402
from core.scope_guard import ScopeGuard  # noqa: E402
from db.models import Database  # noqa: E402

CONFIG = {"timeouts": {"tool_default_seconds": 5}, "tiers": {"tier1": {"naabu_top_ports": 10}}}


class Tier1ActiveTestCase(unittest.TestCase):
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

    def test_in_scope_asset_degrades_gracefully_when_tools_missing(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "domain", "example.com", discovered_by="seed")

        result = tier1_active.run(asset, "example.com", self.guard, self.db, CONFIG, self.evidence)

        # httpx/naabu aren't installed in this sandbox -- the stage should
        # not raise, and should report no live hosts / no open ports rather
        # than crashing the pipeline.
        self.assertFalse(result["live"])
        self.assertEqual(result["open_ports"], 0)

    def test_out_of_scope_asset_is_skipped_not_scanned(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "domain", "not-in-scope.org", discovered_by="seed")

        result = tier1_active.run(asset, "example.com", self.guard, self.db, CONFIG, self.evidence)

        self.assertEqual(result.get("skipped"), "out_of_scope")

    def test_scan_rows_are_recorded_even_when_tool_missing(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "domain", "example.com", discovered_by="seed")

        tier1_active.run(asset, "example.com", self.guard, self.db, CONFIG, self.evidence)

        with self.db.cursor() as cur:
            cur.execute("SELECT tool_name, status FROM scans WHERE target_id = ?", (target.id,))
            rows = {r["tool_name"]: r["status"] for r in cur.fetchall()}
        self.assertIn("httpx", rows)
        self.assertIn("naabu", rows)
        # 'skipped' when the binary is missing, 'failed' if it errored some
        # other way -- either is acceptable here, 'running' (never finished)
        # is not.
        self.assertNotEqual(rows["httpx"], "running")
        self.assertNotEqual(rows["naabu"], "running")

    def test_steps_log_records_the_chain_in_order(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "domain", "example.com", discovered_by="seed")

        tier1_active.run(asset, "example.com", self.guard, self.db, CONFIG, self.evidence)

        steps_log = (self.evidence.root / "steps.log").read_text()
        for expected in ("dnsx", "httpx", "naabu", "subzy", "dnsreaper", "cdncheck", "tlsx-posture"):
            self.assertIn(expected, steps_log)

        steps_jsonl = (self.evidence.root / "steps.jsonl").read_text()
        records = [json.loads(line) for line in steps_jsonl.splitlines() if line.strip()]
        tool_names = [r["tool"] for r in records]
        # dnsx (the resolve check) always runs before httpx/naabu -- that
        # ordering is the whole point of the steps log being append-only.
        self.assertLess(tool_names.index("dnsx"), tool_names.index("httpx"))
        self.assertLess(tool_names.index("dnsx"), tool_names.index("naabu"))


class ExpandSubdomainsTestCase(unittest.TestCase):
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

    def test_degrades_gracefully_when_puredns_missing(self):
        # puredns isn't installed in this sandbox -- expand_subdomains()
        # should return an empty list, not raise.
        target = self.db.get_or_create_target("example.com")
        new_assets = tier1_active.expand_subdomains(
            "example.com", target.id, self.guard, self.db, CONFIG, self.evidence
        )
        self.assertEqual(new_assets, [])

    def test_scan_row_is_recorded_even_when_tool_missing(self):
        target = self.db.get_or_create_target("example.com")
        tier1_active.expand_subdomains("example.com", target.id, self.guard, self.db, CONFIG, self.evidence)
        with self.db.cursor() as cur:
            cur.execute("SELECT tool_name, status FROM scans WHERE target_id = ?", (target.id,))
            rows = {r["tool_name"]: r["status"] for r in cur.fetchall()}
        self.assertIn("puredns", rows)
        self.assertNotEqual(rows["puredns"], "running")


if __name__ == "__main__":
    unittest.main()

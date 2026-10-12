"""Integration tests for core.pipeline.tier2_fuzzing. None of batch 1's
discovery tools (arjun/x8/ffuf/feroxbuster) or batch 2's vuln scanners
(dalfox/corsy/crlfuzz/smuggler/nuclei-full) or the gf/qsreplace glue
utilities are installed in this sandbox, so these exercise the
graceful-degradation path, the scope-violation path, and the anew-backed
"don't re-fuzz a URL already tested in a previous run" behavior -- the
behaviors that matter most for this stage's contract. Tool-specific
parsing is covered in each tool's own test_*.py.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from core.evidence_store import EvidenceStore  # noqa: E402
from core.pipeline import tier2_fuzzing  # noqa: E402
from core.scope_guard import ScopeGuard  # noqa: E402
from db.models import Database  # noqa: E402

CONFIG = {"timeouts": {"tool_default_seconds": 5}}


class Tier2FuzzingTestCase(unittest.TestCase):
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

    def test_degrades_gracefully_when_tools_missing(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        result = tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        # None of batch 1/2's tools are installed in this sandbox -- the
        # stage should not raise, and should report zero new endpoints
        # and zero findings rather than crashing the pipeline.
        self.assertEqual(result["new_endpoints"], 0)
        self.assertEqual(result["findings"], 0)
        self.assertNotIn("skipped", result)

    def test_out_of_scope_asset_is_skipped_not_scanned(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "not-in-scope.org", discovered_by="seed")

        result = tier2_fuzzing.run(
            asset, "https://not-in-scope.org", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        self.assertEqual(result.get("skipped"), "out_of_scope")

    def test_scan_rows_are_recorded_even_when_tool_missing(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        with self.db.cursor() as cur:
            cur.execute("SELECT tool_name, status FROM scans WHERE target_id = ?", (target.id,))
            rows = {r["tool_name"]: r["status"] for r in cur.fetchall()}
        # openredirex isn't in this list -- it only runs against
        # gf-filtered "redirect" candidates, and gf isn't installed here,
        # so the candidate list is empty and openredirex's run() is never
        # called at all (see test_openredirex_is_skipped_without_gf below).
        for tool in ("arjun", "x8", "ffuf", "feroxbuster", "kiterunner", "gospider", "cariddi", "xnlinkfinder",
                     "dalfox", "corsy", "crlfuzz", "smuggler", "testssl", "nuclei-full"):
            self.assertIn(tool, rows)
            self.assertNotEqual(rows[tool], "running")

    def test_openredirex_is_skipped_without_gf(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        with self.db.cursor() as cur:
            cur.execute("SELECT tool_name FROM scans WHERE target_id = ?", (target.id,))
            tool_names = {r["tool_name"] for r in cur.fetchall()}
        self.assertNotIn("openredirex", tool_names)

    def test_dalfox_still_runs_against_live_url_without_gf(self):
        # gf isn't installed -- xss_candidates falls back to [live_url]
        # rather than running dalfox against nothing.
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        with self.db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as n FROM scans WHERE target_id = ? AND tool_name = 'dalfox'", (target.id,))
            count = cur.fetchone()["n"]
        self.assertEqual(count, 1)

    def test_second_run_against_the_same_url_is_skipped_via_anew(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        first = tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )
        second = tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        self.assertNotIn("skipped", first)
        self.assertEqual(second.get("skipped"), "already_tested")

    def test_steps_log_records_the_discovery_chain(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="seed")

        tier2_fuzzing.run(
            asset, "https://app.example.com", "example.com", self.guard, self.db, CONFIG, self.evidence
        )

        steps_log = (self.evidence.root / "steps.log").read_text()
        for expected in ("arjun", "x8", "ffuf", "feroxbuster", "kiterunner", "gospider", "cariddi", "xnlinkfinder",
                         "dalfox", "corsy", "crlfuzz", "smuggler", "testssl", "nuclei-full"):
            self.assertIn(expected, steps_log)


if __name__ == "__main__":
    unittest.main()

"""Tests for db.models.Database -- the sqlite persistence layer."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.models import Database  # noqa: E402


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(path=str(Path(self._tmp.name) / "test.sqlite"))

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()

    def test_get_or_create_target_is_idempotent(self):
        t1 = self.db.get_or_create_target("example.com")
        t2 = self.db.get_or_create_target("example.com")
        self.assertEqual(t1.id, t2.id)

    def test_add_asset_and_list_assets(self):
        target = self.db.get_or_create_target("example.com")
        self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="subfinder")
        self.db.add_asset(target.id, "subdomain", "api.example.com", discovered_by="subfinder")
        assets = self.db.list_assets(target.id)
        self.assertEqual(len(assets), 2)
        self.assertEqual({a.value for a in assets}, {"app.example.com", "api.example.com"})

    def test_add_asset_upsert_does_not_duplicate(self):
        target = self.db.get_or_create_target("example.com")
        self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="subfinder")
        self.db.add_asset(target.id, "subdomain", "app.example.com", discovered_by="subfinder")
        assets = self.db.list_assets(target.id)
        self.assertEqual(len(assets), 1)

    def test_list_assets_by_type_filters_in_sql(self):
        target = self.db.get_or_create_target("example.com")
        self.db.add_asset(target.id, "bucket", "example-bucket")
        self.db.add_asset(target.id, "subdomain", "app.example.com")
        buckets = self.db.list_assets_by_type(target.id, "bucket")
        self.assertEqual([a.value for a in buckets], ["example-bucket"])

    def test_list_asset_values_by_types(self):
        target = self.db.get_or_create_target("example.com")
        self.db.add_asset(target.id, "endpoint", "https://app.example.com/a")
        self.db.add_asset(target.id, "url", "https://app.example.com")
        self.db.add_asset(target.id, "subdomain", "app.example.com")
        values = self.db.list_asset_values_by_types(target.id, ("endpoint", "url"))
        self.assertEqual(set(values), {"https://app.example.com/a", "https://app.example.com"})

    def test_scan_lifecycle(self):
        target = self.db.get_or_create_target("example.com")
        scan_id = self.db.start_scan(target.id, tier=0, tool_name="subfinder")
        self.db.finish_scan(scan_id, status="completed")
        # no exception = pass; a real assertion once a get_scan() helper exists

    def test_findings_round_trip(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "subdomain", "app.example.com")
        finding_id = self.db.add_finding(
            asset.id, title="Open redirect", severity="medium",
            description="test", tier=2,
        )
        findings = self.db.list_findings(target.id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, finding_id)
        self.assertFalse(findings[0].confirmed)

    def test_get_target_returns_none_for_unknown_id(self):
        self.assertIsNone(self.db.get_target(9999))

    def test_get_target_by_raw_input(self):
        created = self.db.get_or_create_target("example.com")
        fetched = self.db.get_target_by_raw_input("example.com")
        self.assertEqual(fetched.id, created.id)

    def test_list_scans_returns_recorded_runs(self):
        target = self.db.get_or_create_target("example.com")
        scan_id = self.db.start_scan(target.id, tier=1, tool_name="httpx")
        self.db.finish_scan(scan_id, status="completed")
        scans = self.db.list_scans(target.id)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].tool_name, "httpx")
        self.assertEqual(scans[0].status, "completed")
        self.assertIsNotNone(scans[0].finished_at)

    def test_list_findings_detailed_includes_asset_and_tool(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "url", "https://app.example.com")
        scan_id = self.db.start_scan(target.id, tier=2, tool_name="dalfox")
        self.db.finish_scan(scan_id, status="completed")
        self.db.add_finding(
            asset.id, title="Possible XSS via parameter 'q'", severity="high",
            description="test", tier=2, scan_id=scan_id, confirmed=True,
        )
        detailed = self.db.list_findings_detailed(target.id)
        self.assertEqual(len(detailed), 1)
        self.assertEqual(detailed[0].asset_value, "https://app.example.com")
        self.assertEqual(detailed[0].tool_name, "dalfox")
        self.assertTrue(detailed[0].confirmed)
        self.assertEqual(detailed[0].evidence, [])

    def test_list_findings_detailed_includes_linked_evidence(self):
        target = self.db.get_or_create_target("example.com")
        asset = self.db.add_asset(target.id, "url", "https://app.example.com")
        finding_id = self.db.add_finding(
            asset.id, title="Possible CRLF injection", severity="medium",
            description="test", tier=2,
        )
        self.db.add_evidence(finding_id, "raw_output", "output/example.com/run1/raw/tier2_crlfuzz.txt")
        detailed = self.db.list_findings_detailed(target.id)
        self.assertEqual(len(detailed[0].evidence), 1)
        self.assertEqual(detailed[0].evidence[0].file_path, "output/example.com/run1/raw/tier2_crlfuzz.txt")

    def test_list_targets(self):
        self.db.get_or_create_target("example.com")
        self.db.get_or_create_target("other.com")
        targets = self.db.list_targets()
        self.assertEqual({t.raw_input for t in targets}, {"example.com", "other.com"})


if __name__ == "__main__":
    unittest.main()

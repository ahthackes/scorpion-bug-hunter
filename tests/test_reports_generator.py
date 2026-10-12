"""Tests for reports.generator.build() -- renders report.md/.html/.json
from a populated db, exercising real grouping/sorting/rendering logic
rather than tool output (that's what test_db.py and each module's own
test_*.py cover).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db.models import Database  # noqa: E402
from reports import generator  # noqa: E402


class ReportGeneratorTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(self._tmp.name)
        self.db = Database(path=str(tmp_path / "test.sqlite"))
        self.out_dir = tmp_path / "output" / "example.com" / "20260101T000000Z"
        self.target = self.db.get_or_create_target("example.com", program_name="Example Bug Bounty")

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()

    def _seed_findings(self):
        asset = self.db.add_asset(self.target.id, "url", "https://app.example.com", discovered_by="httpx")
        scan_id = self.db.start_scan(self.target.id, tier=2, tool_name="dalfox")
        self.db.finish_scan(scan_id, status="completed")
        high_id = self.db.add_finding(
            asset.id, title="Possible XSS via parameter 'q'", severity="high",
            description="Reflected in response body", tier=2, scan_id=scan_id, confirmed=True,
        )
        self.db.add_evidence(high_id, "raw_output", "raw/tier2_app.example.com_dalfox.txt")
        self.db.add_finding(
            asset.id, title="CORS misconfiguration: reflects Origin", severity="medium",
            description="ACAO reflects arbitrary Origin", tier=2, confirmed=False,
        )
        return asset

    def test_raises_for_unknown_target(self):
        with self.assertRaises(ValueError):
            generator.build(9999, self.db, evidence_root=self.out_dir)

    def test_writes_three_report_files(self):
        self._seed_findings()
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        self.assertTrue(Path(paths["markdown"]).exists())
        self.assertTrue(Path(paths["html"]).exists())
        self.assertTrue(Path(paths["json"]).exists())

    def test_clean_scan_still_produces_a_report(self):
        # No findings at all -- the report should say so, not error out.
        self.db.add_asset(self.target.id, "subdomain", "app.example.com")
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        md = Path(paths["markdown"]).read_text()
        self.assertIn("No findings were recorded", md)

    def test_findings_sorted_high_severity_first(self):
        self._seed_findings()
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        md = Path(paths["markdown"]).read_text()
        self.assertLess(md.index("Possible XSS"), md.index("CORS misconfiguration"))

    def test_markdown_includes_remediation_and_evidence(self):
        self._seed_findings()
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        md = Path(paths["markdown"]).read_text()
        self.assertIn("Suggested remediation", md)
        self.assertIn("output-encode", md)  # from the XSS remediation entry
        self.assertIn("raw/tier2_app.example.com_dalfox.txt", md)

    def test_html_includes_severity_badges(self):
        self._seed_findings()
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        html = Path(paths["html"]).read_text()
        self.assertIn('class="badge badge-high"', html)
        self.assertIn('class="badge badge-medium"', html)

    def test_json_report_is_well_formed_and_matches_counts(self):
        self._seed_findings()
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        payload = json.loads(Path(paths["json"]).read_text())
        self.assertEqual(payload["summary"]["total_findings"], 2)
        self.assertEqual(payload["summary"]["confirmed_findings"], 1)
        self.assertEqual(payload["summary"]["severity_counts"]["high"], 1)
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(payload["findings"][0]["evidence"][0]["file_path"],
                          "raw/tier2_app.example.com_dalfox.txt")

    def test_tool_coverage_reflects_scan_status(self):
        asset = self.db.add_asset(self.target.id, "url", "https://app.example.com")
        completed = self.db.start_scan(self.target.id, tier=2, tool_name="dalfox")
        self.db.finish_scan(completed, status="completed")
        skipped = self.db.start_scan(self.target.id, tier=2, tool_name="corsy")
        self.db.finish_scan(skipped, status="skipped")
        paths = generator.build(self.target.id, self.db, evidence_root=self.out_dir)
        payload = json.loads(Path(paths["json"]).read_text())
        coverage = {row["tool_name"]: row for row in payload["tool_coverage"]}
        self.assertEqual(coverage["dalfox"]["completed"], 1)
        self.assertEqual(coverage["corsy"]["skipped"], 1)


if __name__ == "__main__":
    unittest.main()

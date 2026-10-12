"""Tests for core.evidence_store.EvidenceStore -- raw-per-tool-file
persistence and the steps log/jsonl chain record.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.evidence_store import EvidenceStore  # noqa: E402


class EvidenceStoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base_dir = str(Path(self._tmp.name) / "output")

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_raw_writes_a_separate_file_per_tool(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        store.save_raw(tier=0, asset_value="example.com", tool_name="subfinder", raw_output="sub.example.com")
        store.save_raw(tier=0, asset_value="example.com", tool_name="assetfinder", raw_output="app.example.com")

        files = sorted(p.name for p in store.raw_dir.glob("*.txt"))
        self.assertEqual(len(files), 2)
        self.assertTrue(any("subfinder" in f for f in files))
        self.assertTrue(any("assetfinder" in f for f in files))

    def test_save_raw_then_load_raw_round_trips(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        store.save_raw(tier=1, asset_value="app.example.com", tool_name="httpx", raw_output="some raw httpx json")

        loaded = store.load_raw(tier=1, asset_value="app.example.com", tool_name="httpx")
        self.assertEqual(loaded, "some raw httpx json")

    def test_load_raw_returns_none_when_nothing_saved(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        self.assertIsNone(store.load_raw(tier=1, asset_value="app.example.com", tool_name="nuclei"))

    def test_different_assets_dont_clobber_each_others_raw_file(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        store.save_raw(tier=1, asset_value="a.example.com", tool_name="httpx", raw_output="result A")
        store.save_raw(tier=1, asset_value="b.example.com", tool_name="httpx", raw_output="result B")

        self.assertEqual(store.load_raw(tier=1, asset_value="a.example.com", tool_name="httpx"), "result A")
        self.assertEqual(store.load_raw(tier=1, asset_value="b.example.com", tool_name="httpx"), "result B")

    def test_record_step_appends_to_steps_log_and_jsonl(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        store.record_step(tier=0, asset_value="example.com", tool_name="subfinder", status="completed", result_count=5)
        store.record_step(tier=0, asset_value="example.com", tool_name="assetfinder", status="skipped", detail="not installed")

        log_text = (store.root / "steps.log").read_text()
        self.assertIn("subfinder", log_text)
        self.assertIn("assetfinder", log_text)
        self.assertIn("not installed", log_text)

        lines = (store.root / "steps.jsonl").read_text().splitlines()
        records = [json.loads(line) for line in lines]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["tool"], "subfinder")
        self.assertEqual(records[0]["result_count"], 5)
        self.assertEqual(records[1]["status"], "skipped")

    def test_steps_are_appended_in_call_order(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="example.com")
        for tool in ("dnsx", "httpx", "naabu", "nmap"):
            store.record_step(tier=1, asset_value="example.com", tool_name=tool, status="completed")

        records = [json.loads(line) for line in (store.root / "steps.jsonl").read_text().splitlines()]
        self.assertEqual([r["tool"] for r in records], ["dnsx", "httpx", "naabu", "nmap"])

    def test_two_runs_against_the_same_target_get_separate_folders(self):
        store_a = EvidenceStore(base_dir=self.base_dir, target_raw="example.com", run_id="run1")
        store_b = EvidenceStore(base_dir=self.base_dir, target_raw="example.com", run_id="run2")
        self.assertNotEqual(store_a.root, store_b.root)

    def test_target_slug_handles_scheme_and_wildcard(self):
        store = EvidenceStore(base_dir=self.base_dir, target_raw="https://*.example.com/path")
        self.assertIn("example.com", str(store.root))


if __name__ == "__main__":
    unittest.main()

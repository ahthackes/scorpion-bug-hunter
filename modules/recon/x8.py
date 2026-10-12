"""
Wrapper for x8 -- a second, independent hidden-parameter discovery tool
alongside Arjun (modules/recon/arjun.py). Same job, different detection
approach (x8 diffs response size/behavior across requests rather than
Arjun's wordlist+heuristic method), so running both catches parameters
the other misses -- same "two independent sources" reasoning as
httpx+webanalyze for tech fingerprinting in Tier 1. Tier 2.

CLI: x8 -u <url> -O json -o <tmpfile>
x8 writes JSON to -o rather than stdout.

Known JSON shape (array of per-request results):
    [{"url": "...", "method": "GET", "status": 200, "parameters": ["admin"]}]
Entries with no discovered parameters are skipped.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class X8Module(ToolModule):
    name = "x8"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["x8", "-u", target, "-O", "json", "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            return []
        if isinstance(rows, dict):
            rows = [rows]

        assets: list[Asset] = []
        for row in rows:
            params = row.get("parameters", [])
            if not params:
                continue
            url = row.get("url", target_raw)
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="x8",
                    meta={"params": params, "status_code": row.get("status")},
                )
            )
        return assets

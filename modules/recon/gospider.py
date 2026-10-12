"""
Wrapper for gospider -- a second crawler alongside katana.py (Tier 1),
with different crawl heuristics (its own JS-endpoint extraction, sitemap/
robots.txt parsing, and Wayback-aware seeding). Tier 2 here rather than
Tier 1 since it's reusing Tier 2's batch-1 "more discovery before
fuzzing" slot, not because it needs anything fuzzing-specific -- two
crawlers regularly turn up different endpoint sets from the same seed
URL, same reasoning as running both subfinder and amass in Tier 0.

CLI: gospider -s <url> -o <tmpdir> --json -d 2 -c 5
gospider writes one JSON-lines file per target inside -o (named after a
hash of the URL), not stdout -- so run() finds and reads that file back,
then cleans up the directory.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class GospiderModule(ToolModule):
    name = "gospider"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        depth = str(config.get("tiers", {}).get("tier2", {}).get("gospider_depth", 2))
        with tempfile.TemporaryDirectory() as out_dir:
            run_command(
                ["gospider", "-s", target, "-o", out_dir, "--json", "-d", depth, "-c", "5", "-t", "5"],
                timeout=timeout,
            )
            output_files = list(Path(out_dir).glob("*.json")) or list(Path(out_dir).glob("*.txt"))
            if not output_files:
                return ""
            return "\n".join(f.read_text() for f in output_files)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            url = None
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                    url = row.get("output") or row.get("url")
                except json.JSONDecodeError:
                    continue
            if not url or url in seen:
                continue
            seen.add(url)
            assets.append(
                Asset(type=AssetType.ENDPOINT, value=url, target_raw=target_raw, discovered_by="gospider")
            )
        return assets

"""
Wrapper for feroxbuster -- recursive content discovery (unlike ffuf's
single-level fuzz, feroxbuster automatically re-fuzzes any directory it
finds, so it surfaces nested paths ffuf's one-pass sweep would miss).
Tier 2. Runs against the same target/wordlist as ffuf -- the two are
complementary passes (breadth vs depth), same reasoning as
httpx+webanalyze or arjun+x8 elsewhere in this pipeline.

CLI: feroxbuster -u <url> -w <wordlist> --json -q --rate-limit <rps>
feroxbuster streams one JSON object per line to stdout with --json (no
report file needed, unlike ffuf/arjun/nuclei) -- each line has a "type"
field; only "response" rows are actual discovered content, so parse()
filters for those.
"""

from __future__ import annotations

import json
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_DEFAULT_WORDLIST = "config/wordlists/content-small.txt"


class FeroxbusterModule(ToolModule):
    name = "feroxbuster"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        tier2_cfg = config.get("tiers", {}).get("tier2", {})
        wordlist = tier2_cfg.get("content_wordlist", _DEFAULT_WORDLIST)
        if not Path(wordlist).exists():
            raise ToolError(f"feroxbuster wordlist not found at '{wordlist}' -- skipping content discovery")

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        rate = tier2_cfg.get("rate_limit_rps", 10)
        result = run_command(
            [
                "feroxbuster", "-u", target, "-w", wordlist,
                "--json", "-q", "--rate-limit", str(rate),
            ],
            timeout=timeout,
        )
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("type") != "response":
                continue
            url = row.get("url")
            if not url:
                continue
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="feroxbuster",
                    meta={"status_code": row.get("status"), "length": row.get("content_length")},
                )
            )
        return assets

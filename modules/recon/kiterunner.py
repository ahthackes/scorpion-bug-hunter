"""
Wrapper for kiterunner -- purpose-built REST API route/endpoint
discovery, using OpenAPI-spec-derived wordlists (routes + likely HTTP
methods together, not just paths) instead of a generic content wordlist.
Tier 2. Where ffuf/feroxbuster brute-force a flat wordlist of paths,
kiterunner's wordlists encode real API shapes (e.g. "/api/v1/users/{id}")
mined from public API specs, so it's a meaningfully different, often
stronger discovery pass against API-heavy targets specifically.

CLI: kr scan <url> -w <wordlist> -j -o <tmpfile> --ignore-length
     <common_error_body_length>
kiterunner writes JSON-lines, one per found route:
    {"url": "https://example.com/api/v1/users", "method": "GET", "status_code": 200}

Ships with the same default wordlist directory pattern as ffuf/
feroxbuster -- config['tiers']['tier2']['kiterunner_wordlist'], falling
back to the bundled small content list if a dedicated kite wordlist
(e.g. the public kiterunner "routes-large" list) isn't present, since a
real kiterunner wordlist is a large separate download not bundled here.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_DEFAULT_WORDLIST = "config/wordlists/content-small.txt"


class KiterunnerModule(ToolModule):
    name = "kiterunner"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        tier2_cfg = config.get("tiers", {}).get("tier2", {})
        wordlist = tier2_cfg.get("kiterunner_wordlist", _DEFAULT_WORDLIST)
        if not Path(wordlist).exists():
            raise ToolError(f"kiterunner wordlist not found at '{wordlist}' -- skipping API route discovery")

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["kr", "scan", target, "-w", wordlist, "-j", "-o", report_path],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else ""
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = row.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="kiterunner",
                    meta={"method": row.get("method"), "status_code": row.get("status_code")},
                )
            )
        return assets

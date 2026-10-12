"""
Wrapper for ffuf -- fast content/path discovery by fuzzing a wordlist
against a URL (hidden admin panels, backup files, config files, API
routes that aren't linked anywhere but still respond). Tier 2.

CLI: ffuf -u <url>/FUZZ -w <wordlist> -of json -o <tmpfile> -mc <codes> -t <threads>
ffuf writes its JSON report to -o rather than stdout.

JSON shape (ffuf's own documented format):
    {"results": [{"url": "...", "status": 200, "length": 1234, "words": 10, ...}]}

Ships with a small default wordlist (config/wordlists/content-small.txt,
~30 common paths) so this works out of the box, same pattern as
puredns.py's subdomain wordlist -- override via
config['tiers']['tier2']['content_wordlist'] for a real engagement.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_DEFAULT_WORDLIST = "config/wordlists/content-small.txt"
_DEFAULT_MATCH_CODES = "200,204,301,302,307,401,403,405"


class FfufModule(ToolModule):
    name = "ffuf"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        tier2_cfg = config.get("tiers", {}).get("tier2", {})
        wordlist = tier2_cfg.get("content_wordlist", _DEFAULT_WORDLIST)
        if not Path(wordlist).exists():
            raise ToolError(f"ffuf wordlist not found at '{wordlist}' -- skipping content discovery")

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        match_codes = tier2_cfg.get("ffuf_match_codes", _DEFAULT_MATCH_CODES)
        rate = tier2_cfg.get("rate_limit_rps", 10)
        fuzz_url = target.rstrip("/") + "/FUZZ"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                [
                    "ffuf", "-u", fuzz_url, "-w", wordlist,
                    "-of", "json", "-o", report_path,
                    "-mc", match_codes, "-rate", str(rate),
                    "-silent",
                ],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else "{}"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        try:
            report = json.loads(raw_output) if raw_output.strip() else {}
        except json.JSONDecodeError:
            return []

        assets: list[Asset] = []
        for row in report.get("results", []):
            url = row.get("url")
            if not url:
                continue
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="ffuf",
                    meta={"status_code": row.get("status"), "length": row.get("length")},
                )
            )
        return assets

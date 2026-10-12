"""
Wrapper for webanalyze (a Wappalyzer port) -- identifies frameworks,
CMSs, JS libraries, and server software running on a live site. Tier 1.

CLI: webanalyze -host <url> -output json
JSON output: {"hostname": "...", "matches": [{"app": "nginx", "version": ""}, ...]}

A second, independent tech-fingerprint source alongside httpx's built-in
-tech-detect (modules/recon/httpx_probe.py) -- the two use different
detection databases and regularly disagree, so running both gives better
coverage than either alone.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class WebanalyzeModule(ToolModule):
    name = "webanalyze"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["webanalyze", "-host", target, "-output", "json"], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"webanalyze failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        if not raw_output.strip():
            return []
        try:
            row = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        matches = row.get("matches", [])
        if not matches:
            return []
        tech = [m.get("app") for m in matches if m.get("app")]
        return [
            Asset(
                type=AssetType.URL,
                value=target_raw,
                target_raw=target_raw,
                discovered_by="webanalyze",
                meta={"tech": tech},
            )
        ]

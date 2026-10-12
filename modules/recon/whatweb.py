"""
Wrapper for WhatWeb -- a third tech-fingerprint source (alongside httpx's
built-in -tech-detect and webanalyze.py), using yet another signature
database. Tier 1. Same "more sources, more coverage" reasoning as
webanalyze.py's docstring -- these regularly disagree with each other,
and WhatWeb in particular tends to catch older/niche CMS plugins the
other two miss.

CLI: whatweb --log-json=<tmpfile> -a 1 <url>
WhatWeb writes its report to a file (-log-json) rather than cleanly to
stdout, same pattern as wafw00f.py/gitleaks.py. JSON output is a list of
one object per target:
    [{"target": "https://example.com", "plugins": {"nginx": {...}, "WordPress": {...}}}]
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class WhatwebModule(ToolModule):
    name = "whatweb"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["whatweb", f"--log-json={report_path}", "-a", "1", target], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            return []
        if not rows:
            return []
        plugins = rows[0].get("plugins", {})
        tech = sorted(plugins.keys())
        if not tech:
            return []
        return [
            Asset(
                type=AssetType.URL,
                value=target_raw,
                target_raw=target_raw,
                discovered_by="whatweb",
                meta={"tech": tech},
            )
        ]

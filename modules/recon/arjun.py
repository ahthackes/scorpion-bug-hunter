"""
Wrapper for Arjun -- finds hidden HTTP GET/POST parameters a web app
accepts but doesn't link to anywhere (common source of IDOR, debug
flags, and injection points that content-discovery alone never surfaces,
since there's no link or file to find -- the parameter name itself is
the only hint). Tier 2.

CLI: arjun -u <url> -oJ <tmpfile>
Arjun writes a JSON report to -oJ rather than stdout, so run() reads
that file back, same pattern as gitleaks.py/nuclei.py.

Known JSON shape (per Arjun's own docs):
    {"https://example.com/page.php": ["id", "page", "ref"]}
A couple of Arjun versions nest the list one level deeper as
{"params": [...]} -- parse() handles both shapes rather than assuming one.

Each discovered parameter becomes an ENDPOINT Asset (not a Finding --
finding an unlinked parameter isn't itself a vulnerability, it's a new
thing to test), with the parameter names in meta so Tier 2's
param-aware scanners (added in a later batch: dalfox, etc) can build
test URLs from them without re-running Arjun.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class ArjunModule(ToolModule):
    name = "arjun"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["arjun", "-u", target, "-oJ", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "{}"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else {}
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, dict):
            return []

        assets: list[Asset] = []
        for url, value in rows.items():
            if isinstance(value, dict):
                params = value.get("params", [])
            elif isinstance(value, list):
                params = value
            else:
                continue
            if not params:
                continue
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="arjun",
                    meta={"params": params},
                )
            )
        return assets

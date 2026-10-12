"""
Wrapper for nuclei -- the Tier 2 "full template set" pass. Same
underlying tool as Tier 1's safe-mode scan (modules/vuln/nuclei.py), but
without the severity floor or the intrusive/fuzz/dos template exclusion
-- this is deliberately the more aggressive invocation, run only once
per live asset at Tier 2 (after the safe-mode pass already ran at Tier
1), not a replacement for it. Named nuclei_full.py (not nuclei.py) to
keep the two invocations visibly distinct, same reasoning as
nmap_deep.py vs naabu.py.

CLI: nuclei -u <url> -json-export <tmpfile> -silent
     [-interactsh-server <host>]  -- only when configured
(no -severity or -etags flags -- every template category runs)
nuclei writes a JSON array to -json-export, same as the Tier 1 module.

Same optional OOB passthrough as nuclei.py -- see that module's docstring
for why there's no separate "interactsh module" here.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command

_SEVERITY_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


class NucleiFullModule(ToolModule):
    name = "nuclei-full"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tier_default_seconds", 3600)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        args = ["nuclei", "-u", target, "-json-export", report_path, "-silent"]
        interactsh_server = config.get("integrations", {}).get("interactsh_server")
        if interactsh_server:
            args += ["-interactsh-server", interactsh_server]
        try:
            run_command(args, timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            rows = []

        findings: list[Finding] = []
        for row in rows:
            info = row.get("info", {})
            severity_str = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)
            matched_at = row.get("matched-at", target_raw)
            asset = Asset(type=AssetType.URL, value=matched_at, target_raw=target_raw, discovered_by="nuclei-full")
            findings.append(
                Finding(
                    asset=asset,
                    title=info.get("name", row.get("template-id", "nuclei finding")),
                    severity=severity,
                    description=info.get("description", f"nuclei template '{row.get('template-id')}' matched"),
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="nuclei-full",
                    confirmed=True,
                )
            )
        return findings

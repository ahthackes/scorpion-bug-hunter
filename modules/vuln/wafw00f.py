"""
Wrapper for wafw00f -- identifies which Web Application Firewall (if any)
is protecting a site. Tier 1.

CLI: wafw00f <url> -a -f json -o <tmpfile>
wafw00f writes its report to a file (-o) rather than stdout in a cleanly
parseable form, so run() reads that file back, same pattern as gitleaks.py.

Knowing a WAF is present doesn't itself produce a vulnerability -- it's
informational, recorded as an INFO-severity Finding so it shows up in the
report and can inform how later tiers approach that asset (e.g. whether
Tier 2 fuzzing needs more conservative rate limiting to avoid tripping
the WAF's own blocking).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class Wafw00fModule(ToolModule):
    name = "wafw00f"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["wafw00f", target, "-a", "-f", "json", "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            rows = []

        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="wafw00f")
        for row in rows:
            if not row.get("detected"):
                continue
            firewall = row.get("firewall", "unknown WAF")
            manufacturer = row.get("manufacturer", "")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"WAF detected: {firewall}",
                    severity=Severity.INFO,
                    description=f"wafw00f identified {firewall}"
                    + (f" ({manufacturer})" if manufacturer else "")
                    + " protecting this asset",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="wafw00f",
                    confirmed=True,
                )
            )
        return findings

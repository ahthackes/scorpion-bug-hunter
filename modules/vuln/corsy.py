"""
Wrapper for Corsy -- CORS misconfiguration scanner. Tier 2 batch 2.

A misconfigured Access-Control-Allow-Origin (reflecting any Origin,
trusting null, trusting a weak subdomain-matching regex, etc) lets an
attacker's page read authenticated responses cross-origin -- a common
and often-missed finding in bug bounty programs.

CLI: corsy -u <url> -o <tmpfile>
Corsy writes a JSON report to -o rather than stdout.

JSON shape (per Corsy's own output format -- a dict keyed by URL, each
holding a "vulnerable" bool and an "issues" list of misconfiguration
classes it flagged, e.g. "Reflects Origin", "Null Origin Allowed",
"Invalid Regex Allows Arbitrary Origin"):
    {"https://example.com": {"vulnerable": true,
                              "issues": ["Reflects Origin"]}}
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class CorsyModule(ToolModule):
    name = "corsy"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["corsy", "-u", target, "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "{}"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else {}
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, dict):
            return []

        findings: list[Finding] = []
        for url, result in rows.items():
            if not isinstance(result, dict) or not result.get("vulnerable"):
                continue
            asset = Asset(type=AssetType.URL, value=url, target_raw=target_raw, discovered_by="corsy")
            issues = result.get("issues", []) or ["Misconfigured CORS policy"]
            for issue in issues:
                findings.append(
                    Finding(
                        asset=asset,
                        title=f"CORS misconfiguration: {issue}",
                        severity=Severity.MEDIUM,
                        description=f"Corsy flagged {url}'s CORS policy: {issue}",
                        tier=RiskTier.TIER2_FUZZING,
                        tool_name="corsy",
                        confirmed=False,  # a human should confirm the origin check is actually exploitable
                    )
                )
        return findings

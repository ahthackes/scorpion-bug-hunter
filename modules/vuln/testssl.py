"""
Wrapper for testssl.sh -- deep TLS/SSL misconfiguration scanning (weak
ciphers, protocol downgrade, known vulnerability classes like Heartbleed/
POODLE/ROBOT). Tier 2 batch 2. A deeper, slower pass than tlsx's posture
mode (modules/recon/tlsx.py's TlsxPostureModule, Tier 1) -- that one is a
fast handshake-level check run against every asset; this one is a full
protocol audit with a much larger (and slower) test matrix, so it's kept
at Tier 2 alongside the other heavier single-URL scanners rather than in
the per-asset Tier 1 fan-out.

CLI: testssl.sh --jsonfile <tmpfile> --severity MEDIUM --quiet <url>
testssl.sh writes one JSON object per finding/check to --jsonfile (JSON
Lines, not a single array) -- only rows whose own "severity" meets a
genuine weakness (not "OK"/"INFO"/"DEBUG") become Findings here.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command

_SEVERITY_MAP = {
    "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
_NON_FINDING_SEVERITIES = {"ok", "info", "debug", "warn"}


class TestsslModule(ToolModule):
    name = "testssl"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tier_default_seconds", 600)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["testssl.sh", "--jsonfile", report_path, "--severity", "MEDIUM", "--quiet", target],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else ""
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        text = raw_output.strip()
        if not text:
            return []
        # testssl.sh's --jsonfile is a single JSON array in modern
        # versions but JSON-lines in some older ones -- handle both.
        try:
            rows = json.loads(text)
            if isinstance(rows, dict):
                rows = [rows]
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="testssl")
        for row in rows:
            severity_str = (row.get("severity") or "").lower()
            if severity_str in _NON_FINDING_SEVERITIES or severity_str not in _SEVERITY_MAP:
                continue
            findings.append(
                Finding(
                    asset=asset,
                    title=f"TLS issue: {row.get('id', 'unknown check')}",
                    severity=_SEVERITY_MAP[severity_str],
                    description=row.get("finding", "testssl.sh flagged a TLS misconfiguration"),
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="testssl",
                    confirmed=True,
                )
            )
        return findings

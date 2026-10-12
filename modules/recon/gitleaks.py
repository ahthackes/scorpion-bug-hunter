"""
Wrapper for gitleaks -- scans a git repository (already cloned to a local
path) for leaked secrets using regex + entropy rules. Tier 0.

CLI: gitleaks detect --source <local_path> --report-format json
     --report-path <tmpfile> --exit-code 0 --no-banner
gitleaks writes its findings to a report file rather than stdout, so run()
reads that file back rather than parsing stdout directly.

Like trufflehog.py, `target` here is a local filesystem path to an
already-cloned repo, not a domain -- not auto-wired into the per-target
Tier 0 loop yet (see trufflehog.py's docstring for the same caveat and the
Phase 2 TODO to wire up automatic repo discovery).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command

_RULE_SEVERITY = {
    "aws-access-token": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "generic-api-key": Severity.HIGH,
}


class GitleaksModule(ToolModule):
    name = "gitleaks"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.URL  # a local repo path, passed in as a string -- see module docstring

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 600)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                [
                    "gitleaks", "detect",
                    "--source", target,
                    "--report-format", "json",
                    "--report-path", report_path,
                    "--exit-code", "0",
                    "--no-banner",
                ],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            rows = []

        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="gitleaks")
        for row in rows:
            rule = row.get("RuleID", "unknown-rule")
            severity = _RULE_SEVERITY.get(rule, Severity.HIGH)
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Leaked secret: {rule}",
                    severity=severity,
                    description=(
                        f"gitleaks matched rule '{rule}' in "
                        f"{row.get('File', 'unknown file')} (commit {row.get('Commit', '?')[:8]})"
                    ),
                    tier=RiskTier.TIER0_PASSIVE,
                    tool_name="gitleaks",
                    confirmed=False,  # regex/entropy matches always need a human look
                )
            )
        return findings

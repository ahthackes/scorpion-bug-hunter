"""
Wrapper for nuclei -- templated vulnerability/misconfiguration scanning.
This module is nuclei's Tier 1 "safe mode": informational and low/medium
severity templates only, intrusive/fuzzing/DoS-tagged templates excluded.
Tier 2 will reuse the same underlying tool with the full template set
(a separate, more aggressive invocation) once that tier is built -- see
the architecture doc's Tier 2 table.

CLI: nuclei -u <url> -json-export <tmpfile> -severity info,low,medium
     -etags intrusive,dos,fuzz,fuzzing -silent
     [-interactsh-server <host>]  -- only when configured, see below
nuclei writes a JSON array to -json-export rather than clean JSON-lines
to stdout, so run() reads that file back, same pattern as gitleaks.py.

Out-of-band (OOB) detection -- blind SSRF/XXE/RCE templates that need a
callback to confirm, rather than an in-response match -- is nuclei's own
built-in feature, not a separate tool this project wraps: nuclei talks to
a public or self-hosted interactsh server automatically for any OOB-
tagged template it runs. A self-hosted server (set up once, run alongside
this tool) is set via config['integrations']['interactsh_server'] (a
host:port) and passed straight through via -interactsh-server; leaving it
unset lets nuclei fall back to its own default public server rather than
disabling OOB checks outright.
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


class NucleiModule(ToolModule):
    name = "nuclei"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        args = [
            "nuclei", "-u", target,
            "-json-export", report_path,
            "-severity", "info,low,medium",
            "-etags", "intrusive,dos,fuzz,fuzzing",
            "-silent",
        ]
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
            asset = Asset(type=AssetType.URL, value=matched_at, target_raw=target_raw, discovered_by="nuclei")
            findings.append(
                Finding(
                    asset=asset,
                    title=info.get("name", row.get("template-id", "nuclei finding")),
                    severity=severity,
                    description=info.get("description", f"nuclei template '{row.get('template-id')}' matched"),
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="nuclei",
                    confirmed=True,  # a nuclei match is a direct, verified observation
                )
            )
        return findings

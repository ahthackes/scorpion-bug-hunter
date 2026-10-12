"""
Wrapper for dnsReaper -- a second, independent subdomain-takeover
scanner alongside subzy.py, with its own (larger) fingerprint database
of vulnerable-service signatures. subzy.py's docstring originally said
"same job, one tool chosen" and skipped this -- re-added here because the
two tools' fingerprint lists don't fully overlap, and a dangling-CNAME
takeover is cheap enough to check twice for the coverage gain. Tier 1.

CLI: dnsreaper scan single --domain <host> --json-output <tmpfile>
dnsReaper writes its report to a file rather than stdout, same pattern as
wafw00f.py/whatweb.py. JSON output is a list of per-check results:
    [{"domain": "old.example.com", "vulnerable": true,
      "signature_name": "github-pages", "confidence": "high"}, ...]
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class DnsReaperModule(ToolModule):
    name = "dnsreaper"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["dnsreaper", "scan", "single", "--domain", target, "--json-output", report_path],
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
        if isinstance(rows, dict):
            rows = [rows]

        findings: list[Finding] = []
        for row in rows:
            if not row.get("vulnerable"):
                continue
            domain = row.get("domain", target_raw)
            signature = row.get("signature_name", "an unknown service")
            asset = Asset(type=AssetType.SUBDOMAIN, value=domain, target_raw=target_raw, discovered_by="dnsreaper")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Subdomain takeover: {domain}",
                    severity=Severity.HIGH,
                    description=f"dnsReaper flagged {domain} as vulnerable to takeover via a dangling "
                                f"DNS record matching the '{signature}' signature (confidence: "
                                f"{row.get('confidence', 'unknown')}).",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="dnsreaper",
                    confirmed=True,
                )
            )
        return findings

"""
Wrapper for subzy -- subdomain takeover detection (dangling CNAMEs
pointing at an unclaimed third-party service: GitHub Pages, Heroku, S3,
etc). Tier 1. dnsreaper.py runs the same category of check with a second,
independent fingerprint database alongside this one -- see that module's
docstring.

CLI: subzy run --target <host> --json
JSON output: [{"subdomain": "...", "vulnerable": true, "service": "..."}]

A confirmed takeover is a serious, directly-actionable finding (an
attacker can claim the dangling CNAME and serve content from a trusted
subdomain) -- always HIGH severity and confirmed, no heuristic ambiguity
the way a regex-based secret match has.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class SubzyModule(ToolModule):
    name = "subzy"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["subzy", "run", "--target", target, "--json"], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"subzy failed for {target}: {result.stderr.strip()}")
        return result.stdout

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
            subdomain = row.get("subdomain", target_raw)
            service = row.get("service", "an unknown service")
            asset = Asset(type=AssetType.SUBDOMAIN, value=subdomain, target_raw=target_raw, discovered_by="subzy")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Subdomain takeover: {subdomain}",
                    severity=Severity.HIGH,
                    description=(
                        f"{subdomain} has a dangling DNS record pointing at {service}, "
                        f"which appears unclaimed -- an attacker may be able to register "
                        f"it and serve content from this subdomain"
                    ),
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="subzy",
                    confirmed=True,
                )
            )
        return findings

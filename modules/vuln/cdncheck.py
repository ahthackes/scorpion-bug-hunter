"""
Wrapper for cdncheck (ProjectDiscovery) -- flags whether a host sits
behind a CDN/WAF/cloud load balancer. Tier 1. Purely informational (an
INFO-severity Finding, same pattern as wafw00f.py) but useful context:
a host behind Cloudflare/Akamai means its naabu/nmap results describe
the CDN's edge, not the origin server, and later tiers should factor
that in rather than treating an open port 80/443 on a CDN IP as
meaningful by itself.

CLI: cdncheck -silent -json -input <host>
One JSON object, e.g.:
    {"host": "example.com", "cdn": true, "cdn_name": "cloudflare",
     "waf": false, "cloud": false}
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class CdncheckModule(ToolModule):
    name = "cdncheck"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["cdncheck", "-silent", "-json", "-input", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"cdncheck failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        asset = Asset(type=AssetType.SUBDOMAIN, value=target_raw, target_raw=target_raw, discovered_by="cdncheck")
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            provider = row.get("cdn_name") or row.get("waf_name") or row.get("cloud_name") or "unknown provider"
            kind = "CDN" if row.get("cdn") else "WAF" if row.get("waf") else "cloud" if row.get("cloud") else None
            if not kind:
                continue
            findings.append(
                Finding(
                    asset=asset,
                    title=f"{kind} detected: {provider}",
                    severity=Severity.INFO,
                    description=f"cdncheck identified {target_raw} as sitting behind {provider} ({kind}). "
                                f"Port/service scans against this host describe the {kind}'s edge, not "
                                f"necessarily the origin server.",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="cdncheck",
                    confirmed=True,
                )
            )
        return findings

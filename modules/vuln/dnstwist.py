"""
Wrapper for dnstwist -- generates typosquat/homoglyph/bitsquat
permutations of a domain and checks which ones are actually registered
and resolving. Tier 1, run once per root domain (like puredns/dnstwist
itself works from the root domain, not a specific subdomain). Finds
phishing/brand-impersonation infra, not a vulnerability in the target
itself -- informational by nature, but worth flagging since an active
lookalike domain is often an ongoing phishing campaign against the
target's users.

CLI: dnstwist --format json <domain>
JSON array, one object per permutation tried; only entries that actually
resolve (have a "dns-a" or "dns-aaaa" key) are registered/live and worth
a Finding -- the vast majority of permutations dnstwist tries are
unregistered and get skipped here.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class DnstwistModule(ToolModule):
    name = "dnstwist"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("dnstwist_seconds") or config.get(
            "timeouts", {}
        ).get("tool_default_seconds", 300)
        result = run_command(["dnstwist", "--format", "json", target], timeout=max(timeout, 300))
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"dnstwist failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        asset = Asset(type=AssetType.DOMAIN, value=target_raw, target_raw=target_raw, discovered_by="dnstwist")
        for row in rows:
            lookalike = row.get("domain-name") or row.get("domain")
            if not lookalike or lookalike.lower() == target_raw.lower():
                continue
            if not (row.get("dns-a") or row.get("dns-aaaa")):
                continue  # unregistered/non-resolving permutation -- not a live lookalike
            fuzzer = row.get("fuzzer", "unknown")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Possible typosquat domain: {lookalike}",
                    severity=Severity.INFO,
                    description=f"dnstwist found a registered, resolving lookalike domain "
                                f"'{lookalike}' ({fuzzer} permutation of {target_raw}) -- "
                                f"worth checking manually for an active phishing campaign "
                                f"impersonating this target.",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="dnstwist",
                    confirmed=True,
                )
            )
        return findings

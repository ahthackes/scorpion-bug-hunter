"""
Wrapper for asnmap (ProjectDiscovery) -- resolves a domain to the ASN(s)
it's hosted under and lists the full CIDR ranges owned by that ASN. Tier
0, passive (ASN/WHOIS-style lookups, no traffic to the target).

CLI: asnmap -d <domain> -silent -json
Each output line is a JSON object like:
    {"timestamp": "...", "input": "example.com", "as_number": "AS13335",
     "as_name": "CLOUDFLARENET", "as_country": "US", "as_range": ["1.2.3.0/24", ...]}

This is context, not a new scannable host list to fan out over blindly --
a shared-hosting/CDN ASN (Cloudflare, AWS, Akamai) owns ranges with
thousands of unrelated tenants, so these are stored as IP_RANGE assets
for a human to review (e.g. before deciding whether a wider naabu/masscan
sweep of a *dedicated* range makes sense), not something Tier 1 auto-fans
out over.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class AsnmapModule(ToolModule):
    name = "asnmap"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["asnmap", "-d", target, "-silent", "-json"], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"asnmap failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            as_number = row.get("as_number", "")
            as_name = row.get("as_name", "")
            for cidr in row.get("as_range") or []:
                if cidr in seen:
                    continue
                seen.add(cidr)
                assets.append(
                    Asset(
                        type=AssetType.IP_RANGE,
                        value=cidr,
                        target_raw=target_raw,
                        discovered_by="asnmap",
                        meta={"as_number": as_number, "as_name": as_name},
                    )
                )
        return assets

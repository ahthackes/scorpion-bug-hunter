"""
Wrapper for assetfinder (passive subdomain enumeration). Tier 0.

CLI: assetfinder --subs-only <domain>
Plain text output, one hostname per line (no JSON mode) -- a useful second
source alongside subfinder since the two tools pull from different passive
data sources and rarely agree on coverage 1:1.
"""

from __future__ import annotations

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class AssetfinderModule(ToolModule):
    name = "assetfinder"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["assetfinder", "--subs-only", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"assetfinder failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            host = line.strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=host,
                    target_raw=target_raw,
                    discovered_by="assetfinder",
                )
            )
        return assets

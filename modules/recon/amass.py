"""
Wrapper for amass (OWASP Amass) -- a second, independently-sourced passive
subdomain enumerator, run in `-passive` mode so it never sends traffic to
the target itself (the same no-active-recon promise as every other Tier 0
source). Tier 0.

CLI: amass enum -passive -d <domain> -silent
Plain text output, one hostname per line -- amass's default/non-silent
output is a lot noisier (banners, source attribution inline), so -silent
keeps this consistent with the rest of Tier 0's plain-text sources.

Amass pulls from a different (and often larger) set of passive sources
than subfinder -- its own bundled API-key config
(~/.config/amass/config.ini) for things like SecurityTrails/Censys/etc,
most of which are optional; it degrades to whatever sources don't need a
key if that file is missing, same spirit as chaos.py needing
CHAOS_API_KEY but failing soft when it's absent.
"""

from __future__ import annotations

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class AmassModule(ToolModule):
    name = "amass"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        # amass is comparatively slow -- give it a longer default timeout
        # than the other Tier 0 sources rather than sharing their budget.
        timeout = config.get("timeouts", {}).get("amass_seconds") or config.get(
            "timeouts", {}
        ).get("tool_default_seconds", 300)
        result = run_command(["amass", "enum", "-passive", "-d", target, "-silent"], timeout=max(timeout, 300))
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"amass failed for {target}: {result.stderr.strip()}")
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
                    discovered_by="amass",
                )
            )
        return assets

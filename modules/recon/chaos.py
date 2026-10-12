"""
Wrapper for chaos-client (ProjectDiscovery's Chaos DNS dataset). Tier 0.

CLI: chaos -d <domain> -silent
Plain text output, one hostname per line.

Needs a Chaos API key, read from the CHAOS_API_KEY environment variable
(see .env.example) and passed via -key. A missing key is a clean skip.
"""

from __future__ import annotations

import os

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command


class ChaosModule(ToolModule):
    name = "chaos"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        api_key = os.environ.get("CHAOS_API_KEY")
        if not api_key:
            raise ToolError(
                "CHAOS_API_KEY is not set -- skipping chaos "
                "(set it in .env to enable this source)"
            )
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            ["chaos", "-d", target, "-key", api_key, "-silent"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"chaos failed for {target}: {result.stderr.strip()}")
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
                    discovered_by="chaos",
                )
            )
        return assets

"""
Wrapper for subfinder (passive subdomain enumeration). Tier 0.

CLI: subfinder -d <domain> -silent -json
Each output line is a JSON object like:
    {"host": "www.example.com", "input": "example.com", "source": "crtsh"}
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class SubfinderModule(ToolModule):
    name = "subfinder"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["subfinder", "-d", target, "-silent", "-json"], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"subfinder failed for {target}: {result.stderr.strip()}")
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
            host = row.get("host")
            if not host or host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=host,
                    target_raw=target_raw,
                    discovered_by=f"subfinder:{row.get('source', 'unknown')}",
                )
            )
        return assets

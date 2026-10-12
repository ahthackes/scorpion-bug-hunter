"""
Wrapper for cero -- scrapes hostnames out of SSL certificate SANs/CNs for a
domain (an alternative to crt.sh scraping -- crt.go in the architecture
doc's Tier 0 table does the same job against crt.sh directly; cero is used
here because it's a single static binary with a simple CLI). Tier 0.

CLI: cero <domain>
Plain text output, one hostname per line -- certs often list wildcard
entries (*.example.com), which aren't a concrete scannable asset on their
own, so those are kept but tagged in meta rather than treated as a plain
subdomain; the pipeline stage decides whether to expand them.
"""

from __future__ import annotations

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class CeroModule(ToolModule):
    name = "cero"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["cero", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"cero failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            host = line.strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            is_wildcard = host.startswith("*.")
            assets.append(
                Asset(
                    type=AssetType.SUBDOMAIN,
                    value=host,
                    target_raw=target_raw,
                    discovered_by="cero",
                    meta={"wildcard": is_wildcard},
                )
            )
        return assets

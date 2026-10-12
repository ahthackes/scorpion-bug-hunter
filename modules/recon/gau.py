"""
Wrapper for gau (Get All URLs) -- pulls known URLs for a domain from the
Wayback Machine, Common Crawl, and AlienVault OTX. Tier 0. Falls back to
waybackurls automatically if gau isn't installed; waymore (a third option
in the architecture doc's Links table) covers the same ground with more
knobs and can be swapped in here later if gau/waybackurls coverage proves
insufficient.

CLI: gau --json <domain>  (JSON lines; falls back to plain text if the
     installed gau version doesn't support --json)
Fallback: waybackurls <domain>  (always plain text, one URL per line)

This is a different kind of Tier 0 source than the subdomain-enum tools
above: it returns URLs/endpoints (often with query strings), not bare
hostnames, so the output type is ENDPOINT, and a single hostname can
legitimately produce hundreds of entries.
"""

from __future__ import annotations

import json
import shutil

from modules.base import Asset, AssetType, RiskTier, ToolModule, ToolNotInstalled, run_command


class GauModule(ToolModule):
    name = "gau"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        if shutil.which("gau"):
            result = run_command(["gau", "--json", target], timeout=timeout)
            if result.returncode == 0 or result.stdout:
                return result.stdout
            raise RuntimeError(f"gau failed for {target}: {result.stderr.strip()}")
        if shutil.which("waybackurls"):
            result = run_command(["waybackurls", target], timeout=timeout)
            if result.returncode == 0 or result.stdout:
                return result.stdout
            raise RuntimeError(f"waybackurls failed for {target}: {result.stderr.strip()}")
        raise ToolNotInstalled(
            "Neither 'gau' nor 'waybackurls' is installed or on PATH. "
            "Install one of them (see docker/Dockerfile) or skip this module "
            "in config/settings.yaml."
        )

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            url = line
            source = "gau"
            # gau --json output; plain waybackurls/gau-without-json output
            # falls through to the line-is-the-url case below.
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                    url = row.get("url") or line
                except json.JSONDecodeError:
                    url = line
            if url in seen:
                continue
            seen.add(url)
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by=source,
                )
            )
        return assets

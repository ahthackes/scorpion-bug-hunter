"""
Wrapper for katana -- an active web crawler/spider that follows links,
forms, and JS-discovered routes on a live site. Tier 1. Falls back to
hakrawler automatically if katana isn't installed (same fallback pattern
as gau.py / waybackurls).

CLI: katana -u <url> -silent -jc -json   (JSON lines)
Fallback: echo <url> | hakrawler -plain   (plain text, one URL per line,
          read on stdin since hakrawler takes its target that way)

Unlike gau (archived/historical URLs, Tier 0, no traffic to the target),
katana actually crawls the live site -- real Tier 1 traffic.
"""

from __future__ import annotations

import json
import shutil

from modules.base import Asset, AssetType, RiskTier, ToolModule, ToolNotInstalled, run_command


class KatanaModule(ToolModule):
    name = "katana"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        if shutil.which("katana"):
            result = run_command(["katana", "-u", target, "-silent", "-jc", "-json"], timeout=timeout)
            if result.returncode == 0 or result.stdout:
                return result.stdout
            raise RuntimeError(f"katana failed for {target}: {result.stderr.strip()}")
        if shutil.which("hakrawler"):
            result = run_command(["hakrawler", "-plain"], timeout=timeout, input_text=target + "\n")
            if result.returncode == 0 or result.stdout:
                return result.stdout
            raise RuntimeError(f"hakrawler failed for {target}: {result.stderr.strip()}")
        raise ToolNotInstalled(
            "Neither 'katana' nor 'hakrawler' is installed or on PATH. "
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
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                    url = row.get("request", {}).get("endpoint") or row.get("url") or line
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
                    discovered_by="katana",
                )
            )
        return assets

"""
Wrapper for github-subdomains (gwen001/github-subdomains) -- finds
subdomains leaked in public GitHub code/commits. Tier 0.

CLI: github-subdomains -d <domain> -t <token>
Plain text output, one hostname per line.

Needs a GitHub personal access token with at least public-repo search
scope, read from the GITHUB_TOKEN environment variable (see .env.example).
Without a token the tool either fails outright or gets rate-limited to
near-uselessness, so this wrapper treats a missing token as a clean skip
rather than a hard failure.
"""

from __future__ import annotations

import os

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command


class GithubSubdomainsModule(ToolModule):
    name = "github-subdomains"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ToolError(
                "GITHUB_TOKEN is not set -- skipping github-subdomains "
                "(set it in .env to enable this source)"
            )
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            ["github-subdomains", "-d", target, "-t", token],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"github-subdomains failed for {target}: {result.stderr.strip()}")
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
                    discovered_by="github-subdomains",
                )
            )
        return assets

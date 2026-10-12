"""
Wrapper for gitlab-subdomains (gwen001/gitlab-subdomains) -- finds
subdomains leaked in public GitLab code/commits. Tier 0.

CLI: gitlab-subdomains -d <domain> -t <token>
Plain text output, one hostname per line.

Needs a GitLab personal access token with `read_api` scope, read from the
GITLAB_TOKEN environment variable (see .env.example). Same reasoning as
github_subdomains.py: a missing token is a clean skip, not a hard failure.
"""

from __future__ import annotations

import os

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command


class GitlabSubdomainsModule(ToolModule):
    name = "gitlab-subdomains"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        token = os.environ.get("GITLAB_TOKEN")
        if not token:
            raise ToolError(
                "GITLAB_TOKEN is not set -- skipping gitlab-subdomains "
                "(set it in .env to enable this source)"
            )
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            ["gitlab-subdomains", "-d", target, "-t", token],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"gitlab-subdomains failed for {target}: {result.stderr.strip()}")
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
                    discovered_by="gitlab-subdomains",
                )
            )
        return assets

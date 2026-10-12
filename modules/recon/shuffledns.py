"""
Wrapper for shuffledns (ProjectDiscovery) -- fast bulk DNS resolution of a
*known* list of candidate hostnames. Tier 1. Different job from puredns:
puredns brute-forces a wordlist of unknown prefixes against the root
domain; shuffledns here re-validates a batch of hostnames Tier 0's
passive sources already turned up (subfinder/amass/etc candidates often
include stale/dead entries), in one fast bulk pass instead of calling
dnsx once per host.

CLI: shuffledns -d <domain> -list <hosts_file> -r <resolvers_file>
     -mode resolve -silent
Plain text output, one resolved (live) hostname per line -- anything NOT
printed back out didn't resolve and is dropped from the candidate pool.

`target` here is a newline-joined batch of candidate hostnames (not a
single host), written to a temp file since shuffledns takes -list <file>.
Called once per root target in core/pipeline/tier1_active.py's
bulk_resolve(), before the per-asset fan-out loop -- same "runs once
up front" shape as expand_subdomains()/puredns.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_DEFAULT_RESOLVERS = "config/resolvers.txt"


class ShuffledNSModule(ToolModule):
    name = "shuffledns"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        """`target` is a newline-joined list of candidate hostnames, and
        the *domain* they belong to is derived from the first one (-d is
        required by shuffledns but mostly used for its own wildcard
        filtering, not to restrict which hosts in -list get tried).
        """
        hosts = [h for h in target.splitlines() if h.strip()]
        if not hosts:
            return ""
        resolvers = config.get("tiers", {}).get("tier1", {}).get("shuffledns_resolvers", _DEFAULT_RESOLVERS)
        if not Path(resolvers).exists():
            raise ToolError(f"shuffledns resolvers file not found at '{resolvers}' -- skipping bulk resolve")

        root_domain = hosts[0].split(".", 1)[-1] if "." in hosts[0] else hosts[0]
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts) + "\n")
            list_file = f.name
        try:
            result = run_command(
                ["shuffledns", "-d", root_domain, "-list", list_file, "-r", resolvers,
                 "-mode", "resolve", "-silent"],
                timeout=timeout,
            )
            if result.returncode != 0 and not result.stdout:
                raise RuntimeError(f"shuffledns failed: {result.stderr.strip()}")
            return result.stdout
        finally:
            Path(list_file).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            host = line.strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(type=AssetType.SUBDOMAIN, value=host, target_raw=target_raw, discovered_by="shuffledns")
            )
        return assets

"""
Wrapper for puredns (wraps massdns) -- active subdomain brute-forcing with
accurate wildcard filtering. Tier 1 "Subdomain enum (active)". Unlike the
Tier 0 passive sources, this actually sends DNS queries for every
candidate in the wordlist, so it's categorized as active even though it
runs once per root domain (like Tier 0) rather than per already-known
subdomain -- see core/pipeline/tier1_active.py's expand_subdomains(),
which runs this once before the per-asset Tier 1 fan-out loop.

CLI: puredns bruteforce <wordlist> <domain> -r <resolvers_file> -q
Plain text output, one resolved hostname per line.

Ships with small defaults so this works out of the box:
  - wordlist: config/wordlists/subdomains-small.txt (~100 common prefixes)
  - resolvers: config/resolvers.txt (a handful of public DNS resolvers)
Override both via config['tiers']['tier1']['puredns_wordlist'] /
['puredns_resolvers'] -- a real engagement should use a much bigger
wordlist (e.g. SecLists' subdomains-top1million) and a larger, freshly
vetted resolver list.
"""

from __future__ import annotations

from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_DEFAULT_WORDLIST = "config/wordlists/subdomains-small.txt"
_DEFAULT_RESOLVERS = "config/resolvers.txt"


class PurednsModule(ToolModule):
    name = "puredns"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        tier1_cfg = config.get("tiers", {}).get("tier1", {})
        wordlist = tier1_cfg.get("puredns_wordlist", _DEFAULT_WORDLIST)
        resolvers = tier1_cfg.get("puredns_resolvers", _DEFAULT_RESOLVERS)

        if not Path(wordlist).exists():
            raise ToolError(f"puredns wordlist not found at '{wordlist}' -- skipping active brute force")
        if not Path(resolvers).exists():
            raise ToolError(f"puredns resolvers file not found at '{resolvers}' -- skipping active brute force")

        timeout = config.get("timeouts", {}).get("tier_default_seconds", 3600)
        result = run_command(
            ["puredns", "bruteforce", wordlist, target, "-r", resolvers, "-q"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"puredns failed for {target}: {result.stderr.strip()}")
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
                    discovered_by="puredns",
                )
            )
        return assets

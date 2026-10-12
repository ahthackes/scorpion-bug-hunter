"""
Wrapper for naabu (fast port scanning). Tier 1.

CLI: naabu -host <asset> -silent -json -top-ports 100

Each output line is a JSON object like:
    {"host": "app.example.com", "ip": "1.2.3.4", "port": 443}

Defaults to -top-ports 100 rather than a full 1-65535 sweep -- bug bounty
recon rarely needs every port, and a full sweep against every subdomain in
a large scope is slow and easy to mistake for abuse. Override via
config['tiers']['tier1']['naabu_top_ports'] if a program's scope calls for
deeper port coverage.

A subdomain that turned up in passive recon (subfinder, cero, etc.) but
has no DNS A/AAAA record -- common for abandoned cPanel artifacts like
autodiscover./cpanel./webdisk. -- makes naabu exit with "no valid ipv4 or
ipv6 targets were found" rather than an empty result set. That's a normal,
expected outcome (nothing to scan), not a tool failure, so it's treated as
a clean empty result here instead of raising.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command

# Substrings naabu prints to stderr when a host simply doesn't resolve --
# matched case-insensitively against the real stderr text.
_NO_TARGETS_MARKERS = (
    "no valid ipv4 or ipv6 targets",
    "no results found",
)


class NaabuModule(ToolModule):
    name = "naabu"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        top_ports = str(config.get("tiers", {}).get("tier1", {}).get("naabu_top_ports", 100))
        result = run_command(
            ["naabu", "-host", target, "-silent", "-json", "-top-ports", top_ports],
            timeout=timeout,
        )
        stderr_lower = (result.stderr or "").lower()
        if any(marker in stderr_lower for marker in _NO_TARGETS_MARKERS):
            return ""  # host doesn't resolve -- nothing to scan, not a failure
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"naabu failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[tuple[str, int]] = set()
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("host") or row.get("ip")
            port = row.get("port")
            if not host or port is None:
                continue
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            assets.append(
                Asset(
                    type=AssetType.IP,
                    value=f"{host}:{port}",
                    target_raw=target_raw,
                    discovered_by="naabu",
                    meta={"host": host, "ip": row.get("ip"), "port": port},
                )
            )
        return assets

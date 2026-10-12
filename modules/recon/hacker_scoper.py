"""
Wrapper for Hacker-Scoper -- filters a mixed list of URLs/IPs down to what
a program's scope actually allows (supports wildcards, CIDR ranges, Nmap
octet ranges, and regex scopes). Tier 0.

CLI: hackerscoper -f <candidates_file> -l <scope_file> -o <output_file>
     (or -c <company_name> instead of -l to auto-detect scope)

This is a *second*, independent scope filter -- distinct from
core/scope_guard.py, which is this tool's own enforcement layer and is
always consulted before anything active runs regardless of what Hacker-
Scoper says. Hacker-Scoper is useful here for cleaning up a large raw
candidate list (e.g. straight off gau/cero output) before it's even worth
feeding through the rest of the pipeline, or for cross-checking
core/scope_guard.py's own filtering against an independent implementation.

`target` is a path to a file of candidate URLs/IPs, one per line (not a
domain) -- this wrapper is meant to be called with the output of other
Tier 0 modules already written to disk, not auto-wired into the per-domain
loop in core/pipeline/tier0_passive.py.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class HackerScoperModule(ToolModule):
    name = "hacker-scoper"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.URL  # a path to a candidates file -- see module docstring

    def run(self, target: str, config: dict) -> str:
        scope_file = config.get("scope", {}).get("hacker_scoper_scope_file")
        company = config.get("scope", {}).get("company_name")
        if not scope_file and not company:
            raise RuntimeError(
                "Hacker-Scoper needs either config['scope']['hacker_scoper_scope_file'] "
                "or config['scope']['company_name'] set"
            )

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_path = f.name
        try:
            args = ["hackerscoper", "-f", target, "-o", output_path]
            args += ["-l", scope_file] if scope_file else ["-c", company]
            run_command(args, timeout=timeout)
            return Path(output_path).read_text() if Path(output_path).exists() else ""
        finally:
            Path(output_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            entry = line.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            assets.append(
                Asset(
                    type=AssetType.URL,
                    value=entry,
                    target_raw=target_raw,
                    discovered_by="hacker-scoper",
                    meta={"in_scope": True},
                )
            )
        return assets

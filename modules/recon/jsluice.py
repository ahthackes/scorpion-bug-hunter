"""
Wrapper for jsluice -- extracts URLs/endpoints and secrets from JavaScript
source, based on how values are used, not just how they look (fewer false
positives than a pure regex approach like LinkFinder/SecretFinder, which
cover the same two categories in the architecture doc's Links/Secrets
tables and aren't separately implemented here for that reason).

CLI: jsluice urls <js_file>      -- JSON lines of discovered URLs/endpoints
     jsluice secrets <js_file>   -- JSON lines of discovered secrets

`target` is a path to a local JS file (jsluice reads files, not live
URLs) -- this module isn't auto-wired into the per-asset Tier 1 loop yet,
since that would require katana's discovered .js URLs to be downloaded
to disk first. Phase 2 TODO: katana -> download .js files -> jsluice.
Until then, call this directly with a JS file path (e.g. one downloaded
by hand or by a future katana-download step).

Two separate run modes share one module since they're really one tool
invoked two ways; `parse()` implements the primary "urls" mode to satisfy
the ToolModule interface, and `run_secrets`/`parse_secrets` cover the
second mode as documented extra methods.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class JsluiceModule(ToolModule):
    name = "jsluice"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL  # a local JS file path -- see module docstring

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["jsluice", "urls", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"jsluice urls failed for {target}: {result.stderr.strip()}")
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
            url = row.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="jsluice",
                    meta={"method": row.get("method", "GET"), "source_file": target_raw},
                )
            )
        return assets

    def run_secrets(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["jsluice", "secrets", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"jsluice secrets failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse_secrets(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="jsluice")
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = row.get("kind", "unknown")
            severity_str = row.get("severity", "medium").lower()
            severity = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW,
            }.get(severity_str, Severity.MEDIUM)
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Potential secret in JS: {kind}",
                    severity=severity,
                    description=f"jsluice found a '{kind}' pattern in {target_raw}",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="jsluice",
                    confirmed=False,  # pattern match, needs a human look
                )
            )
        return findings

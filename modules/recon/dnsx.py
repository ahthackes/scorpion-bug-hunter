"""
Wrapper for dnsx (fast, multi-purpose DNS resolution). Tier 1.

CLI: dnsx -l <hosts_file> -silent -json -a -resp
Each output line is a JSON object like:
    {"host": "app.example.com", "a": ["1.2.3.4"], "status_code": "NOERROR"}
A host dnsx finds nothing for simply doesn't appear in the output at all.

This module exists mainly to answer one question cheaply before spending
time on httpx/naabu: does this host resolve at all? Passive recon sources
(subfinder, cero, etc.) often surface abandoned subdomains -- cPanel
artifacts like autodiscover./cpanel./webdisk. are a common example -- that
never had or no longer have a DNS record. Resolving first lets Tier 1
skip those cleanly instead of letting httpx and naabu each independently
discover "this doesn't exist" (which is exactly what caused the noisy
naabu errors seen in manual testing -- see naabu.py's docstring for the
other half of that fix).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class DnsxModule(ToolModule):
    name = "dnsx"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(target + "\n")
            hosts_file = f.name
        try:
            result = run_command(
                ["dnsx", "-l", hosts_file, "-silent", "-json", "-a", "-resp"],
                timeout=timeout,
            )
        finally:
            Path(hosts_file).unlink(missing_ok=True)
        # dnsx exits 0 whether or not anything resolved -- empty stdout
        # just means "nothing resolved," not a failure, so no error check
        # against returncode here (unlike most other wrappers).
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("host")
            if not host:
                continue
            assets.append(
                Asset(
                    type=AssetType.IP,
                    value=host,
                    target_raw=target_raw,
                    discovered_by="dnsx",
                    meta={"a": row.get("a", []), "status_code": row.get("status_code")},
                )
            )
        return assets

    def resolves(self, raw_output: str) -> bool:
        """Convenience check the pipeline uses instead of parsing full
        Asset objects just to answer "did this host resolve at all?".
        """
        return any(line.strip() for line in raw_output.splitlines())

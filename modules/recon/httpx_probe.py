"""
Wrapper for httpx (liveness probing + tech fingerprinting headers). Tier 1.
Named httpx_probe.py to avoid shadowing the `httpx` HTTP client library.

CLI: httpx -l <hosts_file> -silent -json -title -tech-detect -status-code -follow-redirects

Each output line is a JSON object like:
    {"url": "https://app.example.com", "status_code": 200, "title": "App",
     "tech": ["nginx", "React"], "webserver": "nginx", "host": "1.2.3.4"}

httpx takes a *file* of hosts, not one host per invocation (that's how the
real tool is meant to be used for batches), but this wrapper is called once
per asset by the Tier 1 pipeline stage to keep per-asset scope checks and
per-asset error handling simple -- a single-host input file is written to a
temp file each call. Revisit this wrapper to batch across an entire
target's subdomains in one httpx call if performance becomes a problem.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class HttpxModule(ToolModule):
    name = "httpx"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(target + "\n")
            hosts_file = f.name
        try:
            result = run_command(
                [
                    "httpx", "-l", hosts_file, "-silent", "-json",
                    "-title", "-tech-detect", "-status-code", "-follow-redirects",
                ],
                timeout=timeout,
            )
        finally:
            Path(hosts_file).unlink(missing_ok=True)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"httpx failed for {target}: {result.stderr.strip()}")
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
            url = row.get("url")
            if not url:
                continue
            assets.append(
                Asset(
                    type=AssetType.URL,
                    value=url,
                    target_raw=target_raw,
                    discovered_by="httpx",
                    meta={
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "tech": row.get("tech", []),
                        "webserver": row.get("webserver"),
                        "host": row.get("host"),
                    },
                )
            )
        return assets

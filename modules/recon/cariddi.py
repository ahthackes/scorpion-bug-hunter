"""
Wrapper for cariddi -- crawls a URL and extracts endpoints/parameters in
one pass. Tier 2. cariddi can also flag secrets and interesting file
extensions, but that facet is skipped here (jsluice.py and trufflehog.py/
gitleaks.py already cover secret detection, and stacking a third
regex-based secret scanner on top adds noise more than coverage) --
this wrapper only consumes its endpoint-discovery output, same shape as
gospider.py/katana.py.

CLI: cariddi -s -json
Takes the target URL on stdin (`echo <url> | cariddi ...`), JSON-lines
output, one object per crawled URL:
    {"url": "https://example.com/api/v1/users", "extension": "", ...}
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class CariddiModule(ToolModule):
    name = "cariddi"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["cariddi", "-s", "-json"], timeout=timeout, input_text=target + "\n")
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"cariddi failed for {target}: {result.stderr.strip()}")
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
                Asset(type=AssetType.ENDPOINT, value=url, target_raw=target_raw, discovered_by="cariddi")
            )
        return assets

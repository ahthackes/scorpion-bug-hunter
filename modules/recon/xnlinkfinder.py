"""
Wrapper for xnLinkFinder -- extracts endpoints/paths referenced inside JS
(and HTML) specifically, rather than crawling links generally. Tier 2.
Complements jsluice.py (which extracts endpoints AND secrets from an
already-downloaded JS file -- see that module's "not auto-wired" note
about needing a local file) -- xnLinkFinder can fetch a URL directly
(`-i <url>`) and crawl/parse its JS on its own, so unlike jsluice it
doesn't need a prior "download the .js files to disk" step and fits
straight into this tier's auto-wired discovery batch.

CLI: xnLinkFinder.py -i <url> -o <tmpfile>
xnLinkFinder writes its results to a file (-o), one discovered path/URL
per line, rather than stdout -- same pattern as wafw00f.py/gitleaks.py.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import urljoin

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class XnLinkFinderModule(ToolModule):
    name = "xnlinkfinder"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            report_path = f.name
        try:
            run_command(["xnLinkFinder.py", "-i", target, "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else ""
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            path = line.strip()
            if not path:
                continue
            # xnLinkFinder emits a mix of absolute URLs and bare paths
            # ("/api/v1/users") -- resolve the latter against the target
            # so every stored asset is a concrete, fetchable URL.
            url = path if path.startswith(("http://", "https://")) else urljoin(target_raw, path)
            if url in seen:
                continue
            seen.add(url)
            assets.append(
                Asset(type=AssetType.ENDPOINT, value=url, target_raw=target_raw, discovered_by="xnlinkfinder")
            )
        return assets

"""
Wrapper for gowitness -- takes a screenshot of a live web asset. Tier 1.

CLI: gowitness scan single --url <url> --screenshot-path <dir> --write-db=false

gowitness writes a PNG file to --screenshot-path rather than printing
anything useful to stdout, so run() returns the path to that directory
and parse() looks inside it for the image gowitness wrote, rather than
parsing stdout/a report file the way the JSON-output tools do.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command


class GowitnessModule(ToolModule):
    name = "gowitness"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        screenshot_dir = tempfile.mkdtemp(prefix="gowitness_")
        run_command(
            [
                "gowitness", "scan", "single",
                "--url", target,
                "--screenshot-path", screenshot_dir,
                "--write-db=false",
            ],
            timeout=timeout,
        )
        # Errors (timeouts, TLS failures, etc) just mean no screenshot was
        # written -- parse() below handles an empty directory as "no
        # evidence captured" rather than run() raising, since a single
        # unreachable asset shouldn't be treated as a tool failure.
        return screenshot_dir

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        screenshot_dir = Path(raw_output) if raw_output else None
        if not screenshot_dir or not screenshot_dir.is_dir():
            return []
        images = sorted(screenshot_dir.glob("*.png"))
        if not images:
            return []
        return [
            Asset(
                type=AssetType.URL,
                value=target_raw,
                target_raw=target_raw,
                discovered_by="gowitness",
                meta={"screenshot_path": str(images[0])},
            )
        ]

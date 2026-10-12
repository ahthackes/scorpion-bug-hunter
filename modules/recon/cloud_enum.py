"""
Wrapper for cloud_enum -- checks AWS/Azure/GCP for storage resources
(S3 buckets, Azure blob containers, GCS buckets) named after the target,
using common permutations of a keyword (the org name derived from the
domain). Tier 0, passive from the target's perspective (it only ever
talks to AWS/Azure/GCP's own endpoints, never the target itself).

CLI: cloud_enum.py -k <keyword> --disable-azure-container (left enabled
     by default; only flags shown here for clarity)
Plain text output; a found/open resource is printed on its own line
containing the resource's hostname, e.g.:
    [found] keyword.s3.amazonaws.com
    [found] keyword.blob.core.windows.net

Results are BUCKET assets for Tier 1's s3scanner.py to then check for
actual public read/write access -- cloud_enum's own output already notes
permission-looking hints sometimes, but s3scanner is the module that
produces a definitive Finding about exposure.
"""

from __future__ import annotations

import re

from modules.base import Asset, AssetType, RiskTier, ToolModule, run_command

# Matches the handful of storage-service hostname suffixes cloud_enum
# checks against, pulled out of whatever free-text line it printed.
_STORAGE_HOST_RE = re.compile(
    r"([a-zA-Z0-9.\-]+\.(?:s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"
    r"|blob\.core\.windows\.net"
    r"|storage\.googleapis\.com"
    r"|digitaloceanspaces\.com))",
    re.IGNORECASE,
)


def _keyword_for(domain: str) -> str:
    """cloud_enum works off a short org keyword, not a full domain -- the
    registrable label without its TLD (e.g. "example" from "example.com"
    or "app.example.co.uk"), which is what people actually name buckets
    after.
    """
    label = domain.split(".")[0] if "." in domain else domain
    return label.lower()


class CloudEnumModule(ToolModule):
    name = "cloud-enum"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        keyword = _keyword_for(target)
        result = run_command(["cloud_enum.py", "-k", keyword], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"cloud_enum failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            if "[found]" not in line.lower():
                continue
            match = _STORAGE_HOST_RE.search(line)
            if not match:
                continue
            host = match.group(1).lower()
            if host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(
                    type=AssetType.BUCKET,
                    value=host,
                    target_raw=target_raw,
                    discovered_by="cloud-enum",
                )
            )
        return assets

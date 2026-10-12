"""
Wrapper for s3scanner -- validates a candidate cloud storage bucket
(found by modules/recon/cloud_enum.py) for actual public read/write
access, across S3-compatible providers. Tier 1, consumes BUCKET-type
assets rather than a URL/subdomain -- see core/pipeline/tier1_active.py's
scan_buckets(), called once per BUCKET asset Tier 0 discovered.

CLI: s3scanner scan --bucket <name> --json
One JSON object per bucket:
    {"name": "example", "exists": true, "bucket_policy": null,
     "permission_allusers_read": "allowed", "permission_allusers_write": "denied"}
Only a bucket that both exists AND has allusers read/write "allowed" is a
real exposure -- most candidate names from cloud_enum don't exist at all
(bucket squatting is common and cloud_enum deliberately over-generates
permutations), so "exists": false is the normal, expected outcome, not a
finding.
"""

from __future__ import annotations

import json

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class S3ScannerModule(ToolModule):
    name = "s3scanner"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.BUCKET

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 60)
        result = run_command(["s3scanner", "scan", "--bucket", target, "--json"], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"s3scanner failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        asset = Asset(type=AssetType.BUCKET, value=target_raw, target_raw=target_raw, discovered_by="s3scanner")
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not row.get("exists"):
                continue
            read_open = row.get("permission_allusers_read") == "allowed"
            write_open = row.get("permission_allusers_write") == "allowed"
            if not (read_open or write_open):
                continue
            access = "publicly readable AND writable" if (read_open and write_open) else (
                "publicly readable" if read_open else "publicly writable"
            )
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Publicly accessible cloud storage bucket ({access})",
                    severity=Severity.CRITICAL if write_open else Severity.HIGH,
                    description=f"s3scanner confirms the bucket '{target_raw}' exists and is {access} "
                                f"by any authenticated/anonymous user.",
                    tier=RiskTier.TIER1_ACTIVE,
                    tool_name="s3scanner",
                    confirmed=True,
                )
            )
        return findings

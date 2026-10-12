"""
Wrapper for smuggler -- HTTP request smuggling detection (CL.TE/TE.CL/
TE.TE desync attacks, where a front-end proxy and back-end server
disagree about where one request ends and the next begins). Tier 2
batch 2.

CLI: smuggler -u <url> -o <tmpfile>
(smuggler.py from defparam/smuggler -- a single-file script invoked as a
binary here; see docker/Dockerfile for how it's put on PATH). Writes a
JSON report to -o.

JSON shape (array of per-technique results):
    [{"technique": "CL.TE", "vulnerable": true, "payload": "...",
      "confidence": "high"}]
Only entries with "vulnerable": true become Findings -- request
smuggling is a HIGH severity, directly actionable issue when confirmed
(it's not a heuristic match the way a WAF-fingerprint or tech-detect is).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class SmugglerModule(ToolModule):
    name = "smuggler"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["smuggler", "-u", target, "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            return []
        if isinstance(rows, dict):
            rows = [rows]

        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="smuggler")
        for row in rows:
            if not row.get("vulnerable"):
                continue
            technique = row.get("technique", "unknown")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Possible HTTP request smuggling ({technique})",
                    severity=Severity.HIGH,
                    description=(
                        f"smuggler flagged {target_raw} as vulnerable to a {technique} desync "
                        f"(confidence: {row.get('confidence', 'unknown')})"
                    ),
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="smuggler",
                    confirmed=True,
                )
            )
        return findings

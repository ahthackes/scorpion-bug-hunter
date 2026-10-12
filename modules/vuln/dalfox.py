"""
Wrapper for dalfox -- XSS scanning, parameter-aware (it doesn't just
throw one generic payload at the whole URL, it reasons about where each
parameter's value lands in the response -- an HTML attribute, inline
JS, a tag body -- and tailors payloads accordingly). Tier 2 batch 2.

CLI: dalfox url <url> --format json -o <tmpfile> --silence --no-color
dalfox writes its JSON report to -o rather than stdout, same pattern as
nuclei.py/wafw00f.py.

JSON shape (array of result objects, per dalfox's own docs):
    [{"type": "V", "param": "q", "payload": "...", "evidence": "...",
      "severity": "Medium", "cwe": "CWE-79", "message_id": 12}]
"type": "V" means dalfox verified the payload actually executed/reflected
(confirmed=True); any other type ("G" for grep-based hint, etc) is a
weaker signal and stays unconfirmed.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command

_SEVERITY_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


class DalfoxModule(ToolModule):
    name = "dalfox"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["dalfox", "url", target, "--format", "json", "-o", report_path, "--silence", "--no-color"],
                timeout=timeout,
            )
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
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="dalfox")
        for row in rows:
            severity = _SEVERITY_MAP.get(str(row.get("severity", "medium")).lower(), Severity.MEDIUM)
            param = row.get("param", "unknown")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Possible XSS via parameter '{param}'",
                    severity=severity,
                    description=(
                        f"dalfox flagged parameter '{param}' as a potential XSS injection point. "
                        f"payload: {row.get('payload', 'n/a')} -- evidence: {row.get('evidence', 'n/a')}"
                    ),
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="dalfox",
                    confirmed=row.get("type") == "V",  # dalfox verified execution/reflection
                )
            )
        return findings

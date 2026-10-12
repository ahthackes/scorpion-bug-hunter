"""
Wrapper for graphql-cop -- checks a GraphQL endpoint for common
misconfigurations: introspection left enabled, field suggestions leaking
schema info, batch queries allowed (DoS/brute-force amplification
vector), missing query depth/complexity limits. Tier 2 batch 2, detection
only -- it reports what's misconfigured, it doesn't go on to actually
extract data through introspection.

CLI: graphql-cop -t <url>/graphql -o <tmpfile>
Only run against a URL that looks like it might expose GraphQL (path
ends in /graphql or /api/graphql) -- see _looks_like_graphql_endpoint()
-- rather than blindly POSTing a GraphQL probe at every URL Tier 2 knows
about.

JSON output, a list of per-check results:
    [{"test": "Introspection Query", "vulnerable": true, "severity": "medium", "detail": "..."}]
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolError, ToolModule, run_command

_SEVERITY_MAP = {
    "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _looks_like_graphql_endpoint(url: str) -> bool:
    lowered = url.lower()
    return "graphql" in lowered


class GraphqlCopModule(ToolModule):
    name = "graphql-cop"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        if not _looks_like_graphql_endpoint(target):
            raise ToolError(f"{target} doesn't look like a GraphQL endpoint -- skipping graphql-cop")
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 60)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(["graphql-cop", "-t", target, "-o", report_path], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else "[]"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            rows = json.loads(raw_output) if raw_output.strip() else []
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="graphql-cop")
        for row in rows:
            if not row.get("vulnerable"):
                continue
            severity = _SEVERITY_MAP.get((row.get("severity") or "medium").lower(), Severity.MEDIUM)
            test_name = row.get("test", "GraphQL misconfiguration")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"GraphQL misconfiguration: {test_name}",
                    severity=severity,
                    description=row.get("detail", f"graphql-cop's '{test_name}' check flagged this endpoint"),
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="graphql-cop",
                    confirmed=True,
                )
            )
        return findings

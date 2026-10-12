"""
Wrapper for wpscan -- WordPress-specific vulnerability scanning (core
version CVEs, vulnerable plugins/themes, exposed usernames, weak config).
Tier 2 batch 2 -- but NOT auto-wired into the per-asset chain in
tier2_fuzzing.py yet, the same way trufflehog/gitleaks/bbscope aren't:
it should only run when the target is actually WordPress, and that
"is this WordPress?" signal (from Tier 1's httpx -tech-detect or
webanalyze pass) currently only gets logged, not persisted to the
assets table -- db/models.py's `assets` table has no column for a tech
fingerprint today. Phase 2 TODO: add a `meta` column to `assets` (or a
small `asset_tech` table) so Tier 1's tech-detect results survive past
the log line, then gate this module's invocation in tier2_fuzzing.py on
"CMS" in that stored tech list. CMSmap (the other CMS-conditional tool
on the original list, covering Joomla/Drupal too) will follow the same
pattern once that storage exists -- not implemented separately here
since it's the same gating problem, not a different one.

CLI: wpscan --url <url> --format json -o <tmpfile> --no-banner
wpscan writes its JSON report to -o rather than stdout.

JSON shape (wpscan's own documented format, trimmed to what parse()
uses): a top-level dict with a "vulnerabilities" list under
"version"/"main_theme"/each entry in "plugins", each vulnerability
having a "title" and a "references" dict that may include "cve".
parse() walks all three locations rather than assuming vulnerabilities
only show up in one of them.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class WpscanModule(ToolModule):
    name = "wpscan"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["wpscan", "--url", target, "--format", "json", "-o", report_path, "--no-banner"],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else "{}"
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        try:
            report = json.loads(raw_output) if raw_output.strip() else {}
        except json.JSONDecodeError:
            return []
        if not isinstance(report, dict):
            return []

        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="wpscan")
        findings: list[Finding] = []

        vuln_groups = []
        version_info = report.get("version")
        if isinstance(version_info, dict):
            vuln_groups.append(("WordPress core", version_info.get("vulnerabilities", [])))
        theme_info = report.get("main_theme")
        if isinstance(theme_info, dict):
            vuln_groups.append((theme_info.get("slug", "theme"), theme_info.get("vulnerabilities", [])))
        for slug, plugin_info in (report.get("plugins") or {}).items():
            if isinstance(plugin_info, dict):
                vuln_groups.append((slug, plugin_info.get("vulnerabilities", [])))

        for component, vulns in vuln_groups:
            for vuln in vulns or []:
                cve = (vuln.get("references") or {}).get("cve", [])
                findings.append(
                    Finding(
                        asset=asset,
                        title=f"{component}: {vuln.get('title', 'known vulnerability')}",
                        severity=Severity.HIGH if cve else Severity.MEDIUM,
                        description=f"wpscan flagged {component} -- {vuln.get('title', 'see references')}"
                        + (f" (CVE: {', '.join(cve)})" if cve else ""),
                        tier=RiskTier.TIER2_FUZZING,
                        tool_name="wpscan",
                        confirmed=True,  # version/plugin-match against a known CVE database, not a heuristic
                    )
                )
        return findings

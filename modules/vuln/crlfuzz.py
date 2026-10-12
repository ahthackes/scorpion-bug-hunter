"""
Wrapper for crlfuzz -- CRLF injection scanning (a request that can smuggle
a literal \\r\\n into the response lets an attacker inject arbitrary
response headers or split the response into a second, attacker-controlled
one -- often chained into reflected XSS or cache poisoning). Tier 2
batch 2.

CLI: crlfuzz -u <url> -o <tmpfile> -s
crlfuzz writes plain text (not JSON) to -o: one vulnerable URL per line,
optionally prefixed with a marker. -s (silent) suppresses the banner.

Line shape (per crlfuzz's own plain output):
    https://example.com/path?x=1
Occasionally prefixed with "[VULN] " depending on version -- parse()
strips any such prefix rather than assuming one exact format.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class CrlfuzzModule(ToolModule):
    name = "crlfuzz"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            report_path = f.name
        try:
            run_command(["crlfuzz", "-u", target, "-o", report_path, "-s"], timeout=timeout)
            return Path(report_path).read_text() if Path(report_path).exists() else ""
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            url = line.strip()
            if not url:
                continue
            for prefix in ("[VULN]", "[VULNERABLE]"):
                if url.startswith(prefix):
                    url = url[len(prefix):].strip()
            if not url.startswith("http"):
                continue
            asset = Asset(type=AssetType.URL, value=url, target_raw=target_raw, discovered_by="crlfuzz")
            findings.append(
                Finding(
                    asset=asset,
                    title="Possible CRLF injection",
                    severity=Severity.MEDIUM,
                    description=f"crlfuzz flagged {url} as accepting a CRLF sequence in the response",
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="crlfuzz",
                    confirmed=True,  # crlfuzz only reports a URL after observing the injected header itself
                )
            )
        return findings

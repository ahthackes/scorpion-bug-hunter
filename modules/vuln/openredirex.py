"""
Wrapper for OpenRedireX -- open redirect scanning. Tier 2 batch 2.

Takes a URL with a FUZZ marker in place of the parameter value it should
try payloads against -- core/pipeline/tier2_fuzzing.py builds that marker
URL via core.url_tools.qsreplace(urls, "FUZZ") before calling this, same
"glue tool feeds the scanner" pattern the whole Tier 2 design is built
around.

CLI: openredirex -u <fuzz_url> -p <payloads_file> -k FUZZ
OpenRedireX writes plain text to stdout: one vulnerable URL per line
(no JSON mode). Ships with a small built-in payload set via
config/wordlists/openredirex-payloads.txt (common bypass patterns --
``//evil.com``, ``/\\evil.com``, ``https:evil.com``, etc); override via
config['tiers']['tier2']['openredirex_payloads'] for a bigger list.
"""

from __future__ import annotations

from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolError, ToolModule, run_command

_DEFAULT_PAYLOADS = "config/wordlists/openredirex-payloads.txt"


class OpenRedireXModule(ToolModule):
    name = "openredirex"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL  # a URL with a FUZZ marker in place of a redirect-looking param's value

    def run(self, target: str, config: dict) -> str:
        if "FUZZ" not in target:
            raise ToolError(f"openredirex target must contain a FUZZ marker, got: {target!r}")

        payloads = config.get("tiers", {}).get("tier2", {}).get("openredirex_payloads", _DEFAULT_PAYLOADS)
        if not Path(payloads).exists():
            raise ToolError(f"openredirex payload file not found at '{payloads}' -- skipping")

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            ["openredirex", "-u", target, "-p", payloads, "-k", "FUZZ"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"openredirex failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            asset = Asset(type=AssetType.URL, value=url, target_raw=target_raw, discovered_by="openredirex")
            findings.append(
                Finding(
                    asset=asset,
                    title="Possible open redirect",
                    severity=Severity.LOW,
                    description=f"openredirex got an off-site redirect from {url}",
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="openredirex",
                    confirmed=True,  # only reports a URL after observing the actual redirect
                )
            )
        return findings

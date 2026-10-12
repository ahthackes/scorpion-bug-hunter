"""
Wrapper for GitDorker -- runs a library of GitHub code-search "dorks"
(queries crafted to surface things like leaked API keys, internal
hostnames, and config files) scoped to a target's domain/org. Tier 0,
passive (it queries GitHub's search API, never the target itself).

Unlike trufflehog.py/gitleaks.py (which need a specific repo URL/path
already in hand), GitDorker takes the domain directly and searches across
*all* of GitHub for that string, so -- like gau/subfinder -- it fits
straight into the per-target Tier 0 loop instead of needing a separate
"first find the repos" step.

CLI: GitDorker.py -tf <token_file> -d <domain> -q <dorks_file>
Needs a GitHub personal access token for API rate limits, read from the
GITHUB_TOKEN environment variable (the same one trufflehog/gitleaks-style
tools typically expect) and written to a throwaway token file since
GitDorker only accepts -tf <file>, not a raw token on the CLI. A missing
token is a clean skip, same pattern as chaos.py/CHAOS_API_KEY.

GitDorker's own output is semi-structured text, one matching GitHub URL
per interesting hit, grouped under the dork that found it:
    [+] Searching in example.com for: "example.com" extension:env
    https://github.com/someuser/somerepo/blob/main/.env
This wrapper treats any github.com/.../blob/... URL line as one Finding
-- genuinely confirming whether it's a real secret needs a human (or
trufflehog/gitleaks) to look at that file, so these are always
unconfirmed.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolError, ToolModule, run_command

_BLOB_URL_PREFIX = "https://github.com/"


class GitDorkerModule(ToolModule):
    name = "gitdorker"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ToolError(
                "GITHUB_TOKEN is not set -- skipping gitdorker "
                "(set it in .env to enable GitHub code-search dorking)"
            )
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(token + "\n")
            token_file = f.name
        try:
            result = run_command(
                ["GitDorker.py", "-tf", token_file, "-d", target, "-q", "all"],
                timeout=timeout,
            )
            if result.returncode != 0 and not result.stdout:
                raise RuntimeError(f"gitdorker failed for {target}: {result.stderr.strip()}")
            return result.stdout
        finally:
            Path(token_file).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        asset = Asset(type=AssetType.DOMAIN, value=target_raw, target_raw=target_raw, discovered_by="gitdorker")
        for line in raw_output.splitlines():
            url = line.strip()
            if not url.startswith(_BLOB_URL_PREFIX) or url in seen:
                continue
            seen.add(url)
            findings.append(
                Finding(
                    asset=asset,
                    title="Possible exposure via GitHub code search",
                    severity=Severity.MEDIUM,
                    description=f"A GitHub code-search dork matched {target_raw} in a public "
                                f"repository file: {url} -- review it by hand to confirm whether "
                                f"it contains a real secret or internal detail.",
                    tier=RiskTier.TIER0_PASSIVE,
                    tool_name="gitdorker",
                    confirmed=False,
                )
            )
        return findings

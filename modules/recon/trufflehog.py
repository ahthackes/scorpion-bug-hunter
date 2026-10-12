"""
Wrapper for trufflehog -- scans a public git repository for leaked secrets
(API keys, credentials, tokens) in its full commit history. Tier 0: only
touches public repo data, never the live target itself.

CLI: trufflehog github --repo=<repo_url> --json
JSON lines, one per verified/unverified secret found.

Unlike the subdomain-enum modules above, `target` here is a repository URL
(e.g. "https://github.com/acme-corp/backend"), not a domain -- this module
is not auto-wired into core/pipeline/tier0_passive.py's per-target loop
yet, since that loop currently only knows domains. It's meant to be called
once repo URLs are known (e.g. surfaced by github_subdomains.py results,
or supplied manually). Wiring up automatic repo discovery -> secrets scan
is a Phase 2 TODO.

Output becomes Findings (not Assets): a leaked secret is itself the thing
worth reporting, not a stepping stone to more recon.
"""

from __future__ import annotations

import json

from modules.base import AssetType, Finding, RiskTier, Severity, ToolModule, run_command

# trufflehog's detector names aren't inherently severity-ranked; a simple
# high-signal allowlist bumps the obviously-critical ones up, everything
# else defaults to high since a verified secret is never "low" in practice.
_CRITICAL_DETECTORS = {"AWS", "GCP", "PrivateKey", "Stripe"}


class TrufflehogModule(ToolModule):
    name = "trufflehog"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.URL  # a repo URL, not a domain -- see module docstring

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 600)
        result = run_command(
            ["trufflehog", "github", f"--repo={target}", "--json"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"trufflehog failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        from modules.base import Asset  # local import to avoid a cycle at module load time

        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = row.get("DetectorName", "unknown")
            verified = row.get("Verified", False)
            severity = Severity.CRITICAL if detector in _CRITICAL_DETECTORS else Severity.HIGH
            if not verified:
                # an unverified match is still worth a look, just not as
                # confidently -- one tier down.
                severity = Severity.HIGH if severity == Severity.CRITICAL else Severity.MEDIUM
            asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="trufflehog")
            findings.append(
                Finding(
                    asset=asset,
                    title=f"Leaked secret: {detector}",
                    severity=severity,
                    description=(
                        f"trufflehog found a {'verified' if verified else 'unverified'} "
                        f"{detector} secret in {row.get('SourceMetadata', {}).get('Data', {})}"
                    ),
                    tier=RiskTier.TIER0_PASSIVE,
                    tool_name="trufflehog",
                    confirmed=bool(verified),
                )
            )
        return findings

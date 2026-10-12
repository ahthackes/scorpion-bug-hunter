"""
Wrapper for tlsx (ProjectDiscovery's TLS toolkit), used two ways at two
tiers from this one binary:

  TlsxModule       -- Tier 0, passive-shaped: scrapes hostnames out of a
                       domain's certificate SAN/CN fields, same job as
                       cero.py (an independent second source -- tlsx and
                       cero don't always agree, since they can hit
                       different CT/cert endpoints).
                       CLI: tlsx -san -cn -silent -host <domain>

  TlsxPostureModule -- Tier 1, needs a live asset: full handshake-level
                       TLS posture (protocol version, cipher, expiry) for
                       findings like an expired cert or a weak/legacy
                       protocol still being accepted.
                       CLI: tlsx -san -cn -silent -json -expired
                            -deprecated-tls -weak-cipher -host <host>

Both subcommands emit one JSON object per line with -json, e.g.:
    {"host": "example.com", "subject_an": ["example.com", "www.example.com"],
     "subject_cn": "example.com", "expired": false, "deprecated_tls": false,
     "weak_cipher": false, "not_after": "2026-01-01T00:00:00Z"}
Passive mode here skips -json (SAN/CN scraping only needs plain hostnames
one per line, matching cero's shape); posture mode always uses -json.
"""

from __future__ import annotations

import json

from modules.base import (
    Asset,
    AssetType,
    Finding,
    RiskTier,
    Severity,
    ToolModule,
    run_command,
)


class TlsxModule(ToolModule):
    """Passive mode: certificate SAN/CN scraping. Tier 0."""

    name = "tlsx"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(["tlsx", "-san", "-cn", "-silent", "-host", target], timeout=timeout)
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"tlsx failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            host = line.strip().lower().lstrip("*.")
            if not host or host in seen:
                continue
            seen.add(host)
            assets.append(
                Asset(type=AssetType.SUBDOMAIN, value=host, target_raw=target_raw, discovered_by="tlsx")
            )
        return assets


class TlsxPostureModule(ToolModule):
    """Active mode: full TLS posture (expiry, deprecated protocol, weak
    cipher) against a live host. Tier 1. Separate tool name ("tlsx-posture")
    from the passive module above so the two never collide in the scans/
    steps-log tables, even though they share one binary.
    """

    name = "tlsx-posture"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.SUBDOMAIN

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            [
                "tlsx", "-silent", "-json", "-expired", "-deprecated-tls", "-weak-cipher",
                "-host", target,
            ],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"tlsx (posture) failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("host", target_raw)
            asset = Asset(type=AssetType.SUBDOMAIN, value=host, target_raw=target_raw, discovered_by="tlsx-posture")

            if row.get("expired"):
                findings.append(
                    Finding(
                        asset=asset, title="Expired TLS certificate", severity=Severity.MEDIUM,
                        description=f"tlsx reports the certificate for {host} has expired "
                                    f"(not_after: {row.get('not_after', 'unknown')}).",
                        tier=RiskTier.TIER1_ACTIVE, tool_name=self.name, confirmed=True,
                    )
                )
            if row.get("deprecated_tls"):
                findings.append(
                    Finding(
                        asset=asset, title="Deprecated TLS protocol accepted", severity=Severity.MEDIUM,
                        description=f"tlsx reports {host} still accepts a deprecated TLS "
                                    f"protocol version (e.g. TLS 1.0/1.1 or SSLv3).",
                        tier=RiskTier.TIER1_ACTIVE, tool_name=self.name, confirmed=True,
                    )
                )
            if row.get("weak_cipher"):
                findings.append(
                    Finding(
                        asset=asset, title="Weak TLS cipher accepted", severity=Severity.LOW,
                        description=f"tlsx reports {host} negotiates a weak/legacy cipher suite.",
                        tier=RiskTier.TIER1_ACTIVE, tool_name=self.name, confirmed=True,
                    )
                )
        return findings

"""
Wrapper for nmap -- targeted service/version detection. Tier 1.

Named nmap_deep.py (not nmap.py) to make clear this is the *targeted*
follow-up to naabu, not a replacement for it: naabu does the broad,
fast port sweep across every asset (see naabu.py), and this module runs
only against the specific host:port pairs naabu already found open --
a full nmap -sV sweep of every subdomain in a large scope is slow and
unnecessary when naabu has already narrowed it down.

CLI: nmap -sV -Pn -p <ports> <host> -oX <tmpfile>
nmap writes XML, not JSON -- run() reads the XML report back from the
temp file rather than parsing stdout.
"""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class NmapDeepModule(ToolModule):
    name = "nmap"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.IP  # a bare host, with ports supplied separately -- see run()

    def run(self, target: str, config: dict, ports: list[int]) -> str:
        """`ports` is required here (not part of the base ToolModule
        signature) -- this module is only ever called with naabu's
        already-discovered open ports, never a blind full-range scan.
        """
        if not ports:
            return ""
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        port_list = ",".join(str(p) for p in ports)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            report_path = f.name
        try:
            run_command(
                ["nmap", "-sV", "-Pn", "-p", port_list, target, "-oX", report_path],
                timeout=timeout,
            )
            return Path(report_path).read_text() if Path(report_path).exists() else ""
        finally:
            Path(report_path).unlink(missing_ok=True)

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        if not raw_output.strip():
            return []
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host_value = addr_el.get("addr") if addr_el is not None else target_raw
            asset = Asset(type=AssetType.IP, value=host_value, target_raw=target_raw, discovered_by="nmap")

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                port_num = port_el.get("portid")
                service_el = port_el.find("service")
                if service_el is None:
                    continue
                name = service_el.get("name", "unknown")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                service_desc = " ".join(p for p in (product, version) if p) or name
                findings.append(
                    Finding(
                        asset=asset,
                        title=f"Service on port {port_num}: {name}",
                        severity=Severity.INFO,
                        description=f"nmap identified {service_desc} running on port {port_num}/tcp",
                        tier=RiskTier.TIER1_ACTIVE,
                        tool_name="nmap",
                        confirmed=True,  # directly observed, not a heuristic match
                    )
                )
        return findings

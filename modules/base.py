"""
The shared interface every tool wrapper implements. The orchestrator and
pipeline stages depend on THIS interface, never on a specific tool -- that's
what lets the pipeline chain modules by input/output type instead of
hardcoded "run X then Y" logic.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class RiskTier(Enum):
    TIER0_PASSIVE = 0
    TIER1_ACTIVE = 1
    TIER2_FUZZING = 2
    TIER3_EXPLOIT = 3


class AssetType(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    ENDPOINT = "endpoint"
    IP_RANGE = "ip_range"     # a CIDR block, e.g. from an ASN lookup (asnmap)
    BUCKET = "bucket"         # a cloud storage bucket candidate (cloud_enum), validated by s3scanner


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Asset:
    type: AssetType
    value: str
    target_raw: str                      # the raw targets.txt line this came from
    discovered_by: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    meta: dict = field(default_factory=dict)   # tool-specific extras (status code, tech, etc.)

    def __hash__(self) -> int:
        return hash((self.type, self.value))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Asset) and self.type == other.type and self.value == other.value


@dataclass
class Finding:
    asset: Asset
    title: str
    severity: Severity
    description: str
    tier: RiskTier
    tool_name: str
    confirmed: bool = False
    evidence_paths: list[str] = field(default_factory=list)


class ToolError(RuntimeError):
    """Raised when a tool wrapper can't run or produces unparseable output."""


class ToolNotInstalled(ToolError):
    """Raised when the underlying binary isn't on PATH. Pipeline stages should
    catch this specifically and skip the module with a warning rather than
    aborting the whole run -- a missing tool shouldn't take down the pipeline.
    """


def run_command(
    args: list[str],
    *,
    timeout: int = 300,
    check: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """Shared subprocess runner every module's run() should use instead of
    calling subprocess directly, so timeout handling and the "binary not
    installed" case are consistent across every wrapper. `input_text` is
    for tools that take their target on stdin instead of as an arg (e.g.
    hakrawler's `echo url | hakrawler`).
    """
    binary = args[0]
    if shutil.which(binary) is None:
        raise ToolNotInstalled(
            f"'{binary}' is not installed or not on PATH. "
            f"Install it (see docker/Dockerfile for the expected tool set) "
            f"or skip this module in config/settings.yaml."
        )
    try:
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"'{binary}' timed out after {timeout}s") from exc


class ToolModule(ABC):
    """Base class for every tool wrapper under modules/."""

    name: str
    tier: RiskTier
    requires: AssetType

    @abstractmethod
    def run(self, target: str, config: dict) -> str:
        """Shell out to the tool (via run_command) and return raw output,
        or a path to a raw-output file for large results. `target` is
        whatever this module needs: a bare domain, a full URL, etc. --
        callers are responsible for passing the right shape (see `requires`).
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_output: str, target_raw: str) -> list[Asset] | list[Finding]:
        """Normalize raw tool output into Assets (recon/discovery tools) or
        Findings (vuln/detection tools). `target_raw` is the original
        targets.txt line, threaded through so every Asset/Finding can trace
        back to it.
        """
        raise NotImplementedError

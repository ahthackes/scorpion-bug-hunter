"""
Validates every discovered asset against program scope before any active
(Tier 1+) module is allowed to touch it. This is the safety boundary of the
whole tool -- nothing active runs without passing through it first.

Two sources of scope, combined:
  1. A program's own file in targets/scope/<program>.json, if one matches
     the asset (see targets/scope/README.md for the shape).
  2. If no program file matches, an *implicit* scope is derived from the
     raw targets.txt line itself -- e.g. pasting `*.example.com` into
     targets.txt is treated as in-scope up to config.scope_rules
     .max_tier_without_override, with Tier 3 always denied unless a real
     program file explicitly sets a higher max_tier.

Global `always_exclude` patterns (config/scope_rules.yaml) are checked
first and can never be overridden by a program file.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeViolation(Exception):
    """Raised when an asset is not allowed at the requested tier. Callers
    must not catch-and-continue past this for an active module -- it means
    stop, not retry.
    """


@dataclass
class ProgramScope:
    name: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    max_tier: int = 2
    implicit: bool = False   # True if derived from targets.txt, not a real scope file


def _hostname(value: str) -> str:
    """Extract a bare hostname from a domain, wildcard pattern, or URL."""
    value = value.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    # strip a leading wildcard for hostname extraction, but keep the pattern
    # itself intact wherever it's used for matching, not here
    return value.split("/")[0]


def _matches(hostname: str, pattern: str) -> bool:
    """fnmatch-based wildcard matching (config.scope_rules.wildcard_matching:
    strict means we take the pattern literally -- `*.example.com` matches
    subdomains via fnmatch's '*', and does NOT also match the bare apex
    unless the apex is listed separately).
    """
    pattern = pattern.strip()
    if "://" in pattern:
        pattern = _hostname(pattern)
    return fnmatch.fnmatch(hostname.lower(), pattern.lower())


class ScopeGuard:
    def __init__(
        self,
        scope_dir: str = "targets/scope",
        global_rules_path: str = "config/scope_rules.yaml",
        enforce: bool = True,
    ):
        """`enforce=False` is a TESTING-ONLY kill switch: every asset is
        treated as allowed at every tier, no scope file or always_exclude
        rule is consulted at all. It exists so the pipeline can be run
        against a whole targets.txt with no scope setup while the tool is
        still being built/tested. Set config['scope']['enforce'] back to
        true (the default) before pointing this at a real bug bounty
        program -- see config/settings.yaml.
        """
        self.scope_dir = Path(scope_dir)
        self.global_rules_path = Path(global_rules_path)
        self.enforce = enforce
        self._programs: list[ProgramScope] = []
        self._always_exclude: list[str] = []
        self._max_tier_without_override = 2
        if self.enforce:
            self._load_global_rules()
            self._load_programs()

    def _load_global_rules(self) -> None:
        if not self.global_rules_path.exists():
            return
        with open(self.global_rules_path) as f:
            data = yaml.safe_load(f) or {}
        defaults = data.get("defaults", {})
        self._always_exclude = defaults.get("always_exclude", [])
        self._max_tier_without_override = defaults.get("max_tier_without_override", 2)

    def _load_programs(self) -> None:
        if not self.scope_dir.exists():
            return
        for path in sorted(self.scope_dir.glob("*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                raise ScopeViolation(f"Could not read scope file {path}: {exc}") from exc
            self._programs.append(
                ProgramScope(
                    name=data.get("program", path.stem),
                    in_scope=data.get("in_scope", []),
                    out_of_scope=data.get("out_of_scope", []),
                    max_tier=data.get("max_tier", self._max_tier_without_override),
                )
            )

    def _find_program(self, hostname: str) -> ProgramScope | None:
        for program in self._programs:
            if any(_matches(hostname, p) for p in program.in_scope):
                return program
        return None

    def _implicit_program(self, raw_target: str) -> ProgramScope:
        """Build an implicit single-target scope straight from a
        targets.txt line, capped at max_tier_without_override.
        """
        pattern = raw_target.strip()
        if "://" not in pattern and not pattern.startswith("*."):
            host = _hostname(pattern)
            # bare "example.com" in targets.txt also covers its subdomains,
            # which is how people paste HackerOne/Bugcrowd scope entries
            patterns = [host, f"*.{host}"]
        else:
            patterns = [_hostname(pattern), pattern if pattern.startswith("*.") else pattern]
        return ProgramScope(
            name=f"implicit:{raw_target}",
            in_scope=patterns,
            out_of_scope=[],
            max_tier=self._max_tier_without_override,
            implicit=True,
        )

    def resolve_program(self, asset_or_raw: str) -> ProgramScope | None:
        """Find the program scope covering this hostname, falling back to
        None if nothing -- including no implicit match -- covers it.
        """
        hostname = _hostname(asset_or_raw)
        return self._find_program(hostname)

    def is_allowed(self, asset_or_raw: str, tier: int, raw_target: str | None = None) -> bool:
        """Check whether `asset_or_raw` may be scanned at `tier`.
        `raw_target` is the original targets.txt line this asset was
        discovered under -- used to build an implicit scope if no program
        file matches. If omitted, falls back to using asset_or_raw itself.
        """
        if not self.enforce:
            return True  # TESTING kill switch -- see __init__'s docstring

        hostname = _hostname(asset_or_raw)

        if any(_matches(hostname, pattern) for pattern in self._always_exclude):
            return False

        program = self._find_program(hostname)
        if program is None:
            program = self._implicit_program(raw_target or asset_or_raw)
            if not any(_matches(hostname, p) for p in program.in_scope):
                return False  # doesn't even match its own implicit pattern

        if any(_matches(hostname, pattern) for pattern in program.out_of_scope):
            return False

        if tier == 3:
            # Tier 3 always needs an explicit, non-implicit program allow
            return (not program.implicit) and program.max_tier >= 3

        return tier <= program.max_tier

    def assert_allowed(self, asset_or_raw: str, tier: int, raw_target: str | None = None) -> None:
        if not self.is_allowed(asset_or_raw, tier, raw_target):
            raise ScopeViolation(
                f"'{asset_or_raw}' is not allowed at Tier {tier} "
                f"(check targets/scope/*.json and config/scope_rules.yaml)"
            )

"""
Wrapper for bbscope -- pulls a program's in-scope target list directly from
HackerOne/Bugcrowd/Intigriti/YesWeHack/Immunefi via their APIs. Tier 0.

CLI (HackerOne example): bbscope h1 -t <token> -o <program_handle> -b
     ( -b restricts to bug-bounty-eligible scope entries only )

This is a scope-ingestion tool, not a per-domain recon tool: `target` here
is the program handle (e.g. "acme-corp" as it appears in the platform's
URL), and the platform (h1/bc/it/ywh/immunefi) plus the auth token come
from config/env, not from targets.txt. Its natural output feeds straight
into targets/scope/<program>.json (see targets/scope/README.md) --
pipe its results through modules.recon.hacker_scoper or hand-review them,
then write the program's scope file once.

Not auto-wired into core/pipeline/tier0_passive.py's per-target loop --
it runs once per *program*, ahead of time, to build the scope file that
everything else in this tool then enforces.
"""

from __future__ import annotations

import os

from modules.base import Asset, AssetType, RiskTier, ToolError, ToolModule, run_command

_PLATFORM_FLAGS = {"h1": "h1", "bugcrowd": "bc", "intigriti": "it", "yeswehack": "ywh", "immunefi": "immunefi"}


class BbscopeModule(ToolModule):
    name = "bbscope"
    tier = RiskTier.TIER0_PASSIVE
    requires = AssetType.DOMAIN  # `target` is actually a program handle -- see module docstring

    def run(self, target: str, config: dict) -> str:
        platform = config.get("scope", {}).get("platform", "h1")
        flag = _PLATFORM_FLAGS.get(platform)
        if flag is None:
            raise ToolError(f"Unknown bbscope platform '{platform}' (expected one of {sorted(_PLATFORM_FLAGS)})")

        token_env = f"{platform.upper()}_API_TOKEN"
        token = os.environ.get(token_env)
        if not token:
            raise ToolError(
                f"{token_env} is not set -- skipping bbscope "
                f"(set it in .env to pull scope for '{target}' automatically)"
            )

        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        result = run_command(
            ["bbscope", flag, "-t", token, "-o", target, "-b"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"bbscope failed for program '{target}': {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for line in raw_output.splitlines():
            entry = line.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            assets.append(
                Asset(
                    type=AssetType.DOMAIN,
                    value=entry,
                    target_raw=target_raw,
                    discovered_by="bbscope",
                    meta={"program": target_raw},
                )
            )
        return assets

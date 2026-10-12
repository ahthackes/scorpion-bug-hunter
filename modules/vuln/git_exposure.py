"""
Checks whether a live site accidentally deployed its .git directory --
a common, high-value find (a full source checkout, often with secrets in
history, readable by anyone). Tier 1.

This is a two-line HTTP check, not a dedicated scanning framework, so
rather than depend on a less common tool (git-dumper and similar aren't
packaged anywhere reliable), it's implemented natively here with `curl`
(already a baseline dependency -- see docker/Dockerfile) the same way
core/url_tools.py prefers a thin real-tool wrapper but keeps the logic
simple enough to not need one.

Request: GET <url>/.git/HEAD
A real exposed .git directory's HEAD file is tiny and always starts with
"ref: refs/" (or is a 40-char commit hash in detached-HEAD state) -- a
200 with that exact shape is treated as confirmed; a 200 with different
content (most likely a custom 404 page that doesn't bother returning a
real 404 status) is still flagged, just unconfirmed.
"""

from __future__ import annotations

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command

_STATUS_MARKER = "\nHTTP_STATUS:"


class GitExposureModule(ToolModule):
    name = "git-exposure"
    tier = RiskTier.TIER1_ACTIVE
    requires = AssetType.URL

    def run(self, target: str, config: dict) -> str:
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 30)
        url = target.rstrip("/") + "/.git/HEAD"
        result = run_command(
            ["curl", "-s", "-k", "--max-time", str(min(timeout, 30)), "-w", _STATUS_MARKER + "%{http_code}", url],
            timeout=timeout,
        )
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        if _STATUS_MARKER not in raw_output:
            return []
        body, _, status = raw_output.rpartition(_STATUS_MARKER)
        if status.strip() != "200":
            return []
        body = body.strip()
        looks_like_real_head = body.startswith("ref: refs/") or (len(body) == 40 and all(c in "0123456789abcdef" for c in body.lower()))

        asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="git-exposure")
        return [
            Finding(
                asset=asset,
                title="Exposed .git directory",
                severity=Severity.HIGH,
                description=f"{target_raw.rstrip('/')}/.git/HEAD returned HTTP 200"
                             + (" with real git HEAD content" if looks_like_real_head else " -- verify manually, "
                                "the response didn't look like a real git HEAD file (could be a soft-404 page)")
                             + ". If real, the full .git history (including past commits/secrets) is "
                               "likely downloadable from this path.",
                tier=RiskTier.TIER1_ACTIVE,
                tool_name="git-exposure",
                confirmed=looks_like_real_head,
            )
        ]

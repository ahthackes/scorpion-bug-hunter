"""
Wrapper for SSRFmap -- SSRF exploitation/detection via a captured HTTP
request with a parameter marked as the injection point, confirmed
out-of-band through an interactsh callback server. Tier 2 batch 2 --
but NOT auto-wired into the per-asset chain in tier2_fuzzing.py, for the
same reason trufflehog/gitleaks/bbscope aren't: its input shape doesn't
fit the "one live URL in, Findings out" pattern every other Tier 2
module uses.

SSRFmap needs a raw captured HTTP request file (Burp-style, with a
parameter's value replaced by the marker "SSRFMAP") plus a running
interactsh client to receive the out-of-band callback that actually
confirms the SSRF (a same-process check can't tell the difference
between "no SSRF" and "SSRF fired but we never heard back"). Building
that -- capturing a real request through the asset's live URL, picking
which parameter to mark, standing up an interactsh session and polling
it -- is real infrastructure, not a thin wrapper, so it's scoped out of
this batch. Phase 2 TODO: once Tier 2's arjun/x8 output is used to pick
a parameter automatically (see arjun.py/x8.py's meta["params"]), build
the request file from that and wire interactsh polling through here.

CLI (once wired): ssrfmap -r <request_file> -p <param> -m readfiles
    (or another SSRFmap module depending on what's being probed for)
Until then, call this directly with a hand-captured request file.
"""

from __future__ import annotations

from modules.base import Asset, AssetType, Finding, RiskTier, Severity, ToolModule, run_command


class SsrfmapModule(ToolModule):
    name = "ssrfmap"
    tier = RiskTier.TIER2_FUZZING
    requires = AssetType.URL  # a path to a captured request file -- see module docstring

    def run(self, target: str, config: dict) -> str:
        """`target` is a path to a captured HTTP request file with a
        parameter's value replaced by the SSRFMAP marker, not a bare URL
        -- this module is never called with a live URL directly.
        """
        timeout = config.get("timeouts", {}).get("tool_default_seconds", 300)
        param = config.get("tiers", {}).get("tier2", {}).get("ssrfmap_param", "url")
        result = run_command(
            ["ssrfmap", "-r", target, "-p", param, "-m", "readfiles"],
            timeout=timeout,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"ssrfmap failed for {target}: {result.stderr.strip()}")
        return result.stdout

    def parse(self, raw_output: str, target_raw: str) -> list[Finding]:
        """SSRFmap's console output isn't structured JSON -- it prints a
        human-readable summary per module it tried. This looks for its
        own "[+]" success marker lines; anything it doesn't recognize is
        left unparsed rather than guessed at, since a false positive here
        (claiming SSRF that interactsh never actually confirmed) is worse
        than reporting nothing.
        """
        findings: list[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line.startswith("[+]"):
                continue
            asset = Asset(type=AssetType.URL, value=target_raw, target_raw=target_raw, discovered_by="ssrfmap")
            findings.append(
                Finding(
                    asset=asset,
                    title="Possible SSRF",
                    severity=Severity.HIGH,
                    description=f"ssrfmap reported: {line[3:].strip()}",
                    tier=RiskTier.TIER2_FUZZING,
                    tool_name="ssrfmap",
                    confirmed=False,  # needs interactsh callback confirmation -- see module docstring
                )
            )
        return findings

"""
Generic, defensive remediation guidance keyed off a finding's title --
purely hardening advice (patch, validate, restrict, rotate), never
exploitation detail. This is not a vulnerability database, just a short,
maintainable lookup for the vuln classes Tier 1/Tier 2 actually detect,
used to make reports/generator.py's output more actionable than a bare
tool-output dump.

Keep entries generic enough to survive new tools being added -- match on
a handful of keywords in the finding title rather than a specific tool
name, so a new scanner that produces an "XSS"-titled finding gets useful
guidance without this file needing an update.
"""

from __future__ import annotations

# (keywords to match against the lowercased title, guidance text).
# First match wins, so more specific entries should stay near the top.
_GUIDANCE: list[tuple[tuple[str, ...], str]] = [
    (
        ("xss", "cross-site scripting"),
        "Validate and output-encode all user-controlled input before it's reflected into "
        "an HTML/JS/attribute context. Prefer a templating engine that auto-escapes by "
        "default, and add a strict Content-Security-Policy as defense in depth.",
    ),
    (
        ("cors misconfiguration",),
        "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins. "
        "Never reflect the request's Origin header verbatim, and never combine a wildcard "
        "or reflected origin with Access-Control-Allow-Credentials: true.",
    ),
    (
        ("crlf",),
        "Strip or reject CR/LF characters from any user input before it is written into an "
        "HTTP header, redirect target, or log line. Use a framework API that sets headers "
        "safely rather than building raw header strings by concatenation.",
    ),
    (
        ("open redirect",),
        "Validate redirect targets against an allowlist of known-safe paths or domains "
        "instead of trusting a user-supplied URL parameter directly.",
    ),
    (
        ("smuggling",),
        "Make sure the front-end proxy/load balancer and the back-end server agree on how "
        "to parse ambiguous Content-Length/Transfer-Encoding combinations; normalize or "
        "reject requests with conflicting values at the edge, and keep both tiers on HTTP/2 "
        "end-to-end where possible.",
    ),
    (
        ("ssrf",),
        "Validate and allowlist any server-side outbound request target. Block requests to "
        "internal/link-local/cloud-metadata IP ranges, and disable automatic redirect "
        "following in the HTTP client making the request.",
    ),
    (
        ("subdomain takeover",),
        "Remove the dangling DNS record pointing at the deprovisioned third-party service, "
        "or reclaim the resource on that provider, before someone else registers it.",
    ),
    (
        ("leaked secret", "potential secret in js", "secret in js"),
        "Rotate the exposed credential immediately, purge it from source/version-control "
        "history (not just the latest commit), and add a pre-commit secret scanner to "
        "catch recurrences before they're pushed.",
    ),
    (
        ("known vulnerability",),
        "Update the affected component (plugin/theme/core) to the patched version named in "
        "the finding's description, or disable/remove it if no patch is available yet.",
    ),
    (
        ("waf detected",),
        "Informational only -- no remediation needed. Useful context for how aggressively "
        "later scanning stages should expect to be filtered or rate-limited.",
    ),
    (
        ("service on port",),
        "Confirm this service is meant to be internet-facing. If not, firewall it off at "
        "the network layer. If it must be exposed, make sure it's patched, not running "
        "with default credentials, and covered by its own hardening checklist.",
    ),
]

_DEFAULT = "Review this finding manually to confirm real-world impact and exploitability before deciding on remediation."


def suggest(title: str) -> str:
    """Best-effort remediation blurb for a finding title. Always returns
    something -- an unmatched title falls back to a generic "verify by
    hand" note rather than an empty string, since reports/generator.py
    always renders a remediation line per finding.
    """
    haystack = title.lower()
    for keywords, guidance in _GUIDANCE:
        if any(keyword in haystack for keyword in keywords):
            return guidance
    return _DEFAULT

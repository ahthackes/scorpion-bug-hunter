"""
Small "glue" utilities Tier 2 uses to prep URL lists between scanners --
anew, gf, qsreplace, unfurl, uro in the original tool list. Unlike the
ToolModule wrappers under modules/, these don't fit the run(target)/
parse(raw_output) shape: each one transforms a *list* of URLs into
another list, not "scan one target, get Assets/Findings back."

Every function here tries the real Kali binary first (when it adds real
value -- gf's pattern-matching, uro's redundancy heuristics) and falls
back to a plain-Python equivalent when the binary isn't installed, so
Tier 2 degrades gracefully exactly like every ToolModule does, rather
than skipping URL prep entirely just because one small utility is
missing. qsreplace and unfurl's "extract query keys" mode are simple
enough that the Python version IS the primary implementation -- the real
binary is tried first only for consistency with how a user might already
have their environment set up.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit

logger = logging.getLogger("scorpion.url_tools")


def _run_stdin_tool(binary: str, args: list[str], lines: list[str], timeout: int = 60) -> list[str] | None:
    """Run a binary that reads newline-separated input on stdin and writes
    newline-separated output on stdout. Returns None (never raises) if the
    binary isn't installed or the call fails some other way, so callers
    can fall back to a Python equivalent.
    """
    if not lines or shutil.which(binary) is None:
        return None
    try:
        result = subprocess.run(
            [binary, *args],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("%s failed, falling back to Python equivalent: %s", binary, exc)
        return None
    if result.returncode != 0 and not result.stdout.strip():
        return None
    return [line for line in result.stdout.splitlines() if line.strip()]


def uro_filter(urls: list[str]) -> list[str]:
    """Dedupe/filter a URL list down to the structurally-unique ones --
    uro's real job is collapsing near-duplicates (same path, different
    values for the same params) that waste fuzzing time scanning the same
    thing over and over. Falls back to an exact-match dedupe (order
    preserved) when uro isn't installed -- weaker, but still removes the
    most obvious redundancy.
    """
    out = _run_stdin_tool("uro", [], urls)
    if out is not None:
        return out
    seen: set[str] = set()
    deduped: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            deduped.append(url)
    return deduped


def gf_filter(urls: list[str], pattern: str) -> list[str]:
    """Filter a URL list down to ones matching a named gf pattern (e.g.
    'xss', 'ssrf', 'redirect') -- gf's patterns live in ~/.gf/*.json and
    are a community-maintained set of regexes for "URLs worth fuzzing for
    this vuln class." Returns an empty list (not the full input) when gf
    or that pattern isn't available, since an unfiltered list passed to a
    vuln-class scanner defeats the point of filtering -- callers should
    treat an empty result as "nothing flagged," not "gf failed."
    """
    out = _run_stdin_tool("gf", [pattern], urls)
    return out or []


def kxss_filter(urls: list[str]) -> list[str]:
    """Filter a URL list down to ones where a parameter value is
    genuinely reflected unfiltered in the response -- kxss actually sends
    each URL a request and checks the response, unlike gf_filter's static
    regex match on the URL text alone. That makes it a stronger (if
    slower) signal for "worth handing to dalfox," so Tier 2 unions this
    with gf_filter's "xss"-pattern matches rather than picking one over
    the other. Same "no Python fallback, empty list if unavailable"
    contract as gf_filter -- kxss's actual-request behavior isn't
    something worth half-replicating locally.
    """
    out = _run_stdin_tool("kxss", [], urls)
    if not out:
        return []
    urls_found: list[str] = []
    seen: set[str] = set()
    for line in out:
        match = line.split("URL: ", 1)
        if len(match) != 2:
            continue
        url = match[1].split(" ", 1)[0].strip()
        if url and url not in seen:
            seen.add(url)
            urls_found.append(url)
    return urls_found


def qsreplace(urls: list[str], payload: str) -> list[str]:
    """Replace every query-string value in each URL with `payload`, one
    output URL per input URL with a query string (URLs without one are
    dropped, same as the real qsreplace). This is simple enough that the
    Python version is authoritative -- the real binary is tried first
    only to match the real tool's exact behavior/edge cases when it's
    available.
    """
    out = _run_stdin_tool("qsreplace", [payload], urls)
    if out is not None:
        return out

    replaced: list[str] = []
    for url in urls:
        parts = urlsplit(url)
        if not parts.query:
            continue
        params = parse_qs(parts.query, keep_blank_values=True)
        new_query = "&".join(f"{key}={payload}" for key in params)
        replaced.append(urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)))
    return replaced


def unfurl_keys(urls: list[str]) -> list[str]:
    """Extract the unique query-parameter names used across a URL list
    (unfurl's 'keys' mode) -- useful recon on its own (what parameters
    does this app actually use?) and as input to parameter-aware fuzzing
    later. Python is authoritative here too, same reasoning as qsreplace.
    """
    out = _run_stdin_tool("unfurl", ["keys"], urls)
    if out is not None:
        return sorted(set(out))

    keys: set[str] = set()
    for url in urls:
        query = urlsplit(url).query
        if not query:
            continue
        keys.update(parse_qs(query, keep_blank_values=True).keys())
    return sorted(keys)


def anew(state_file: str, candidates: list[str]) -> list[str]:
    """Append-only dedup against a growing file: returns only the
    candidates NOT already present in `state_file`, and appends them to
    it. Used to avoid re-testing URLs Tier 2 already fuzzed in a previous
    run against the same target -- the chain-memory half of anew's job
    (gf/uro/qsreplace work within one run; anew works across runs).
    Falls back to the same logic in pure Python when the `anew` binary
    isn't installed, since its behavior is simple enough to replicate
    exactly.
    """
    path = Path(state_file)
    existing: set[str] = set()
    if path.exists():
        existing = {line.strip() for line in path.read_text().splitlines() if line.strip()}

    new_items = [c for c in candidates if c not in existing]
    if not new_items:
        return []

    if shutil.which("anew") is not None:
        try:
            subprocess.run(
                ["anew", str(path)],
                input="\n".join(new_items) + "\n",
                capture_output=True,
                text=True,
                timeout=30,
            )
            return new_items
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("anew failed, falling back to a direct file append: %s", exc)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for item in new_items:
            f.write(item + "\n")
    return new_items

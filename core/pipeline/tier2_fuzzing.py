"""
Tier 2 -- Fuzzing & vulnerability detection. Runs once per live
subdomain/asset (same granularity as Tier 1), only against assets Tier 1
found a live URL for -- fuzzing a host that isn't even serving HTTP
wastes time and noise. Elevated request volume relative to Tier 1, so
every tool here respects config.tiers.tier2.rate_limit_rps.

Batch 1 -- parameter + content discovery, the tools everything else in
Tier 2 depends on for URL candidates:

  1. uro      -- dedupe the URL list Tier 0/1 already collected for this
                  asset (gau archives + katana crawl + the live URL
                  itself) before spending fuzzing budget on near-dupes
  2. arjun    -- hidden GET/POST parameter discovery
  3. x8       -- a second, independent parameter-discovery pass
  4. ffuf     -- content/path discovery (single-level fuzz)
  5. feroxbuster -- recursive content discovery (follows directories
                  ffuf finds)
  6. kiterunner -- API route discovery using OpenAPI-derived wordlists,
                  a stronger pass than ffuf/feroxbuster specifically for
                  REST API-shaped targets
  7. gospider -- a second crawler alongside Tier 1's katana, different
                  crawl heuristics, catches different endpoints
  8. cariddi  -- crawl + endpoint extraction in one pass
  9. xnlinkfinder -- extracts endpoints referenced inside a live page's
                  JS directly (fetches the URL itself, unlike jsluice.py
                  which needs an already-downloaded JS file)

Every new endpoint/parameter these turn up is persisted as a new
ENDPOINT asset -- the same "becomes a new asset for the next pass"
pattern katana uses in Tier 1 -- so batch 2 below has real candidate
URLs to test, not just the one live URL Tier 1 handed over.

Batch 2 -- the vuln-class scanners, using batch 1's (plus Tier 0/1's)
URL list as candidates:

 10. gf + kxss + qsreplace -- gf statically matches URLs that *look*
                  XSS/redirect-relevant; kxss actually requests each
                  candidate and confirms real parameter reflection; the
                  two are unioned for XSS candidates (more coverage than
                  either alone), then qsreplace builds FUZZ-marker URLs
                  for the redirect scanner below (every candidate list
                  capped, so this can't become an unbounded fan-out)
 11. dalfox   -- XSS scanning against the gf+kxss candidates
 12. openredirex -- open redirect scanning against qsreplace'd candidates
 13. corsy    -- CORS misconfiguration (run once, against the live URL)
 14. crlfuzz  -- CRLF injection (run once, against the live URL)
 15. smuggler -- HTTP request smuggling (run once, against the live URL)
 16. testssl  -- deep TLS/SSL misconfiguration audit (run once, against
                  the live URL; a slower, more thorough follow-up to
                  Tier 1's tlsx posture check)
 17. graphql-cop -- GraphQL misconfiguration checks (introspection,
                  batching, missing depth limits), only against
                  candidate URLs that look like a GraphQL endpoint
 18. nuclei (full template set) -- run once, against the live URL;
                  Tier 1 already ran nuclei in safe mode, this is the
                  more aggressive follow-up (see nuclei_full.py). Nuclei's
                  own out-of-band/interactsh support covers blind SSRF/
                  XXE-class templates here too -- see nuclei_full.py's
                  docstring for the optional interactsh-server config.
 19. anew     -- records every URL tested this run into a per-target
                  state file, so a later run against the same target
                  skips what's already been tested instead of redoing it

Not auto-wired into this chain (see each module's own docstring for
why): SSRFmap (needs a captured request -- interactsh itself is covered
via nuclei's built-in OOB support, see above) and wpscan/CMSmap (should
only run when the target is confirmed WordPress/a known CMS, and that
signal isn't persisted anywhere yet -- db/models.py's assets table has
no tech column today).

Findings from this tier are unconfirmed by default (Finding.confirmed =
False) unless the tool itself directly observed the issue (crlfuzz,
openredirex, smuggler, nuclei, testssl, graphql-cop) rather than
inferring it heuristically (corsy) -- Tier 3 or a human is still the
final word either way.
"""

from __future__ import annotations

import logging

from core.evidence_store import EvidenceStore
from core.scope_guard import ScopeGuard, ScopeViolation
from core.url_tools import anew, gf_filter, kxss_filter, qsreplace, uro_filter
from db.models import AssetRow, Database
from modules.base import Finding, ToolError, ToolNotInstalled
from modules.recon.arjun import ArjunModule
from modules.recon.cariddi import CariddiModule
from modules.recon.feroxbuster import FeroxbusterModule
from modules.recon.ffuf import FfufModule
from modules.recon.gospider import GospiderModule
from modules.recon.kiterunner import KiterunnerModule
from modules.recon.x8 import X8Module
from modules.recon.xnlinkfinder import XnLinkFinderModule
from modules.vuln.corsy import CorsyModule
from modules.vuln.crlfuzz import CrlfuzzModule
from modules.vuln.dalfox import DalfoxModule
from modules.vuln.graphql_cop import GraphqlCopModule
from modules.vuln.nuclei_full import NucleiFullModule
from modules.vuln.openredirex import OpenRedireXModule
from modules.vuln.smuggler import SmugglerModule
from modules.vuln.testssl import TestsslModule

logger = logging.getLogger("scorpion.tier2")

# Batch 1: discovery modules that take a single URL and return new
# ENDPOINT assets -- run in sequence, same "one bad tool never blocks
# the rest" contract as every other tier.
DISCOVERY_MODULES = [
    ArjunModule, X8Module, FfufModule, FeroxbusterModule,
    KiterunnerModule, GospiderModule, CariddiModule, XnLinkFinderModule,
]

# Batch 2: vuln-class scanners that take a single URL and return
# Findings, run once against the live URL (not fanned out over every
# candidate -- see MULTI_CANDIDATE_MODULES below for the two that are).
SINGLE_URL_VULN_MODULES = [CorsyModule, CrlfuzzModule, SmugglerModule, NucleiFullModule, TestsslModule]

# How many candidate URLs graphql-cop gets run against -- most assets
# have zero GraphQL-looking URLs, in which case this is simply empty.
MAX_GRAPHQL_CANDIDATES = 3

# How many gf-filtered candidate URLs dalfox/openredirex each get run
# against -- a cap, not a tuning knob, so one asset with hundreds of
# matching URLs can't turn Tier 2 into an unbounded scan.
MAX_FUZZ_CANDIDATES = 5


def _gather_known_urls(asset: AssetRow, live_url: str, db: Database) -> list[str]:
    """Collect every URL/endpoint already known for this target (gau
    archives from Tier 0, katana's crawl from Tier 1, batch 1's own
    arjun/x8/ffuf/feroxbuster finds, the live URL itself) -- the
    candidate pool both uro's dedupe pass and the gf-filtered vuln
    scanners draw from. Called twice in `run()` below: once before batch
    1 (for uro) and once after (so batch 2 sees what batch 1 just found).
    """
    urls = {live_url}
    urls.update(db.list_asset_values_by_types(asset.target_id, ("endpoint", "url")))
    return sorted(urls)


def run(
    asset: AssetRow,
    live_url: str,
    target_raw: str,
    guard: ScopeGuard,
    db: Database,
    config: dict,
    evidence: EvidenceStore,
) -> dict:
    """Run both Tier 2 batches against a single live asset: discovery
    (uro -> arjun/x8/ffuf/feroxbuster) then vuln-class scanning
    (gf/qsreplace -> dalfox/openredirex/corsy/crlfuzz/smuggler/full
    nuclei), gated by anew so a target already fuzzed in a previous run
    isn't redone. Returns a small summary dict the orchestrator can log;
    persists new endpoints and findings to the database and raw
    output/step records to `evidence` as it goes.
    """
    try:
        guard.assert_allowed(asset.value, tier=2, raw_target=target_raw)
    except ScopeViolation as exc:
        logger.warning("Tier 2 skipped for %s: %s", asset.value, exc)
        return {"new_endpoints": 0, "findings": 0, "skipped": "out_of_scope"}

    # --- uro: dedupe what's already known before spending fuzzing budget ---
    known_urls = _gather_known_urls(asset, live_url, db)
    deduped = uro_filter(known_urls)
    if len(deduped) < len(known_urls):
        logger.debug(
            "%s: uro deduped %d known URL(s) down to %d before Tier 2 fuzzing",
            asset.value, len(known_urls), len(deduped),
        )

    # --- anew: skip whatever this target has already been fuzzed with ------
    state_file = str(evidence.root / "tier2_tested_urls.txt")
    new_to_test = anew(state_file, [live_url])
    if not new_to_test:
        logger.info("%s: already fuzzed in a previous run (see %s) -- skipping Tier 2", asset.value, state_file)
        return {"new_endpoints": 0, "findings": 0, "skipped": "already_tested"}

    # --- batch 1: arjun, x8, ffuf, feroxbuster ------------------------------
    new_endpoint_count = 0
    for module_cls in DISCOVERY_MODULES:
        new_endpoint_count += _run_discovery_module(
            module_cls, live_url, target_raw, asset, db, config, evidence
        )

    # --- batch 2: vuln-class scanners ---------------------------------------
    finding_count = 0

    # Re-gather now that batch 1 may have added new endpoints -- the
    # gf-filtered candidates below should see them too.
    all_urls = _gather_known_urls(asset, live_url, db)

    # gf's static URL-text match and kxss's actual-request reflection test
    # are unioned rather than one replacing the other -- gf catches URLs
    # that merely *look* XSS-prone (param named "q", "search", etc.) even
    # before any request is sent, kxss confirms real reflection but only
    # for params it actually tested; together they cover more candidates
    # than either alone, still capped at MAX_FUZZ_CANDIDATES total.
    xss_candidates = list(dict.fromkeys([*gf_filter(all_urls, "xss"), *kxss_filter(all_urls)]))
    xss_candidates = (xss_candidates or [live_url])[:MAX_FUZZ_CANDIDATES]
    for url in xss_candidates:
        finding_count += _run_vuln_module(DalfoxModule, url, target_raw, asset, db, config, evidence)

    # openredirex substitutes its own payload list into this FUZZ marker
    # (see openredirex.py's docstring) -- qsreplace just builds the
    # marker URL, it isn't the actual test payload.
    redirect_candidates = qsreplace(gf_filter(all_urls, "redirect"), "FUZZ")
    for url in redirect_candidates[:MAX_FUZZ_CANDIDATES]:
        finding_count += _run_vuln_module(OpenRedireXModule, url, target_raw, asset, db, config, evidence)

    for module_cls in SINGLE_URL_VULN_MODULES:
        finding_count += _run_vuln_module(module_cls, live_url, target_raw, asset, db, config, evidence)

    # graphql-cop: only against URLs that look like a GraphQL endpoint --
    # its own run() also guards this, but filtering here avoids spinning
    # up a scan row for every obviously-irrelevant URL.
    graphql_candidates = [u for u in all_urls if "graphql" in u.lower()][:MAX_GRAPHQL_CANDIDATES]
    for url in graphql_candidates:
        finding_count += _run_vuln_module(GraphqlCopModule, url, target_raw, asset, db, config, evidence)

    return {"new_endpoints": new_endpoint_count, "findings": finding_count}


def _run_discovery_module(
    module_cls, url: str, target_raw: str, asset: AssetRow, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Run one batch-1 discovery module against a URL, persist any new
    endpoints it finds as assets, save its raw output + a step record,
    and return how many new assets it produced. Any failure (missing
    binary, missing wordlist, tool crash) is caught here -- the same
    graceful-degradation contract as every other tier.
    """
    module = module_cls()
    scan_id = db.start_scan(asset.target_id, tier=2, tool_name=module.name)
    try:
        raw = module.run(url, config)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, url)
        return 0
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, url, exc)
        return 0
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, url, exc)
        return 0

    try:
        found = module.parse(raw, target_raw)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(
            tier=2, asset_value=url, tool_name=module.name, status="failed",
            detail=f"couldn't parse output: {exc}",
        )
        logger.error("%s produced unparseable output for %s: %s", module.name, url, exc)
        return 0

    db.finish_scan(scan_id, status="completed")
    for ep in found:
        db.add_asset(asset.target_id, "endpoint", ep.value, discovered_by=module.name)
    raw_file = evidence.save_raw(tier=2, asset_value=url, tool_name=module.name, raw_output=raw)
    evidence.record_step(
        tier=2, asset_value=url, tool_name=module.name,
        status="completed", raw_file=raw_file, result_count=len(found),
    )
    if found:
        logger.info("%s: %s found %d new endpoint/parameter(s)", url, module.name, len(found))
    return len(found)


def _persist_findings(
    db: Database, db_asset_id: int, scan_id: int | None, findings: list[Finding], raw_file: str = ""
) -> int:
    """Same contract as tier1_active._persist_findings -- inserts each
    Finding and, when `raw_file` is already known, links it via the
    evidence table so reports/generator.py can cite the exact raw-output
    file backing each finding.
    """
    for finding in findings:
        finding_id = db.add_finding(
            db_asset_id,
            title=finding.title,
            severity=finding.severity.value,
            description=finding.description,
            tier=finding.tier.value,
            scan_id=scan_id,
            confirmed=finding.confirmed,
        )
        if raw_file:
            db.add_evidence(finding_id, "raw_output", raw_file)
    return len(findings)


def _run_vuln_module(
    module_cls, url: str, target_raw: str, asset: AssetRow, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Run one batch-2 vuln-class scanner against a URL, persist any
    Findings it produces, save its raw output + a step record, and
    return how many findings it produced. Same graceful-degradation
    contract as `_run_discovery_module` above -- a missing binary or a
    malformed URL (openredirex needs its FUZZ marker) just means this
    one scanner is skipped, never a crashed Tier 2 run.
    """
    module = module_cls()
    scan_id = db.start_scan(asset.target_id, tier=2, tool_name=module.name)
    try:
        raw = module.run(url, config)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, url)
        return 0
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, url, exc)
        return 0
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=2, asset_value=url, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, url, exc)
        return 0

    try:
        findings = module.parse(raw, target_raw)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(
            tier=2, asset_value=url, tool_name=module.name, status="failed",
            detail=f"couldn't parse output: {exc}",
        )
        logger.error("%s produced unparseable output for %s: %s", module.name, url, exc)
        return 0

    db.finish_scan(scan_id, status="completed")
    raw_file = evidence.save_raw(tier=2, asset_value=url, tool_name=module.name, raw_output=raw)
    count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
    evidence.record_step(
        tier=2, asset_value=url, tool_name=module.name,
        status="completed", raw_file=raw_file, result_count=count,
    )
    if count:
        logger.warning("%s: %s found %d finding(s)", url, module.name, count)
    return count

"""
Tier 1 -- Active, non-intrusive. Runs once per live subdomain/asset
discovered in Tier 0 (per the fan-out model). Normal GET requests + SYN/
connect port scans only, no payloads.

Chain, per asset:
  1. dnsx          -- does this host even resolve? (skips the rest cleanly
                       if not, instead of letting httpx/naabu each
                       independently discover "nothing's here")
  2. httpx          -- liveness + tech fingerprint
  3. naabu          -- broad port sweep
  4. nmap           -- targeted service/version detection, ONLY on the
                       specific ports naabu found open (naabu's open-port
                       assets are passed straight into nmap's call -- a
                       live example of one tool's result feeding the
                       next)
  5. subzy          -- subdomain takeover check
  6. if httpx found a live URL, also run:
       gowitness    -- screenshot
       webanalyze   -- second tech-fingerprint source
       wafw00f      -- WAF detection
       katana       -- crawl for more endpoints (stored as new assets,
                        which the orchestrator's next pass can fan out
                        over just like any Tier 0-discovered asset)
       nuclei       -- safe-mode template scan (info/low/medium severity,
                        intrusive/fuzz/dos templates excluded -- Tier 2
                        reuses nuclei with the full template set later)

Every step is independently try/except'd (one tool failing never blocks
the rest), and every call is scope-checked again before it runs -- an
asset being in scope for discovery doesn't automatically mean every tool
invoked against it is, and re-checking here is cheap insurance against a
scope file changing between tiers.

`evidence` (an EvidenceStore, see core/evidence_store.py) is threaded
through every step below: each tool's raw output is saved to its own
file, and a line is appended to the run's steps log/jsonl recording what
ran, against what, with what outcome, and where its raw output landed --
so the whole chain can be audited after the fact, and a later step can
read an earlier one's exact raw output back off disk via
`evidence.load_raw()` if it ever needs to.
"""

from __future__ import annotations

import logging

from core.evidence_store import EvidenceStore
from core.scope_guard import ScopeGuard, ScopeViolation
from core.utils import normalize_domain
from db.models import AssetRow, Database
from modules.base import Finding, ToolError, ToolNotInstalled
from modules.recon.dnsx import DnsxModule
from modules.recon.gowitness import GowitnessModule
from modules.recon.httpx_probe import HttpxModule
from modules.recon.katana import KatanaModule
from modules.recon.naabu import NaabuModule
from modules.recon.nmap_deep import NmapDeepModule
from modules.recon.puredns import PurednsModule
from modules.recon.shuffledns import ShuffledNSModule
from modules.recon.tlsx import TlsxPostureModule
from modules.recon.whatweb import WhatwebModule
from modules.vuln.cdncheck import CdncheckModule
from modules.vuln.dnsreaper import DnsReaperModule
from modules.vuln.dnstwist import DnstwistModule
from modules.vuln.git_exposure import GitExposureModule
from modules.vuln.nuclei import NucleiModule
from modules.vuln.s3scanner import S3ScannerModule
from modules.vuln.subzy import SubzyModule
from modules.vuln.wafw00f import Wafw00fModule
from modules.vuln.webanalyze import WebanalyzeModule

logger = logging.getLogger("scorpion.tier1")


def expand_subdomains(
    target_raw: str,
    target_id: int,
    guard: ScopeGuard,
    db: Database,
    config: dict,
    evidence: EvidenceStore,
) -> list[AssetRow]:
    """Active subdomain brute-forcing (puredns/massdns), run ONCE per root
    target before the per-asset Tier 1 fan-out loop -- not once per
    already-known subdomain, since it works from a wordlist of candidate
    prefixes against the root domain, not a specific host. Any new
    subdomains it resolves are scope-checked and persisted exactly like
    Tier 0's sources, then returned so the caller can fold them into the
    fan-out alongside whatever Tier 0 already found.

    A missing binary, a missing wordlist/resolvers file (ToolError), or
    any other failure here just means "no extra subdomains from brute
    force" -- it never blocks the rest of Tier 1.
    """
    root_domain = normalize_domain(target_raw)
    scan_id = db.start_scan(target_id, tier=1, tool_name="puredns")
    try:
        module = PurednsModule()
        raw = module.run(root_domain, config)
        candidates = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=root_domain, tool_name="puredns", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=root_domain, tool_name="puredns",
            status="completed", raw_file=raw_file, result_count=len(candidates),
        )
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="puredns", status="skipped", detail=str(exc))
        logger.warning("%s -- puredns skipped for %s", exc, root_domain)
        return []
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="puredns", status="skipped", detail=str(exc))
        logger.info("puredns skipped for %s: %s", root_domain, exc)
        return []
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="puredns", status="failed", detail=str(exc))
        logger.error("puredns failed for %s: %s", root_domain, exc)
        return []

    new_assets: list[AssetRow] = []
    for candidate in candidates:
        if not guard.is_allowed(candidate.value, tier=1, raw_target=target_raw):
            logger.debug("dropping %s -- not in scope for Tier 1", candidate.value)
            continue
        row = db.add_asset(target_id, "subdomain", candidate.value, discovered_by="puredns")
        new_assets.append(row)

    if new_assets:
        logger.info("puredns brute-forced %d new in-scope subdomain(s) for %s", len(new_assets), root_domain)
    return new_assets


def bulk_resolve(
    target_raw: str, target_id: int, candidate_hosts: list[str], db: Database, config: dict, evidence: EvidenceStore
) -> set[str]:
    """Bulk-validate Tier 0's full candidate list in one shuffledns pass,
    run once per root target before the per-asset fan-out -- a cheap
    efficiency/coverage pre-check, not a replacement for the per-asset
    dnsx gate in run() below (that stays the authoritative "should this
    asset's Tier 1 chain continue" check; this is extra, non-blocking
    context about the batch as a whole). Returns the subset of
    `candidate_hosts` shuffledns confirms resolving -- an empty set on
    any failure, never raises.
    """
    if not candidate_hosts:
        return set()
    root_domain = normalize_domain(target_raw)
    scan_id = db.start_scan(target_id, tier=1, tool_name="shuffledns")
    try:
        module = ShuffledNSModule()
        raw = module.run("\n".join(candidate_hosts), config)
        resolved = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=root_domain, tool_name="shuffledns", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=root_domain, tool_name="shuffledns",
            status="completed", raw_file=raw_file, result_count=len(resolved),
        )
        logger.info("shuffledns bulk-resolved %d/%d candidate(s) for %s", len(resolved), len(candidate_hosts), root_domain)
        return {a.value for a in resolved}
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="shuffledns", status="skipped", detail=str(exc))
        logger.warning("%s -- shuffledns skipped for %s", exc, root_domain)
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="shuffledns", status="skipped", detail=str(exc))
        logger.info("shuffledns skipped for %s: %s", root_domain, exc)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=root_domain, tool_name="shuffledns", status="failed", detail=str(exc))
        logger.error("shuffledns failed for %s: %s", root_domain, exc)
    return set()


def check_typosquats(
    target_raw: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Run dnstwist once per root target -- lookalike/phishing domain
    discovery, unrelated to the per-asset fan-out, so it's persisted
    against the root domain itself rather than any one subdomain. Returns
    the number of findings persisted.
    """
    root_domain = normalize_domain(target_raw)
    domain_asset = db.add_asset(target_id, "domain", root_domain, discovered_by="seed")
    return _run_finding_module(DnstwistModule, root_domain, target_raw, domain_asset, db, config, evidence)


def scan_buckets(
    target_raw: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Run s3scanner against every BUCKET-type asset Tier 0's cloud_enum
    found for this target, once per root target (buckets aren't
    per-subdomain, so this doesn't belong in the per-asset fan-out
    loop). Returns the number of findings persisted.
    """
    buckets = [a for a in db.list_assets(target_id) if a.type == "bucket"]
    if not buckets:
        return 0
    total = 0
    for bucket in buckets:
        total += _run_finding_module(S3ScannerModule, bucket.value, target_raw, bucket, db, config, evidence)
    return total


def _persist_findings(
    db: Database, db_asset_id: int, scan_id: int | None, findings: list[Finding], raw_file: str = ""
) -> int:
    """Insert each Finding, and -- when the caller already has the raw
    tool-output file for this step -- link the two via the evidence table
    so reports/generator.py can cite exactly which raw file backs each
    finding. `raw_file` is optional because a few callers persist
    findings before the raw file is written; those just don't get a
    linked evidence row (the steps.log entry still has the raw path).
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


def _check_resolves(
    host: str, target_raw: str, db: Database, target_id: int, config: dict, evidence: EvidenceStore
) -> bool:
    """Returns True if the host resolves (or if dnsx isn't installed, in
    which case we can't tell and fall back to letting httpx/naabu find
    out themselves rather than blocking the rest of Tier 1).
    """
    scan_id = db.start_scan(target_id, tier=1, tool_name="dnsx")
    try:
        module = DnsxModule()
        raw = module.run(host, config)
        resolved = module.resolves(raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=host, tool_name="dnsx", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=host, tool_name="dnsx", status="completed",
            raw_file=raw_file, detail="resolves" if resolved else "no DNS record",
        )
        return resolved
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=host, tool_name="dnsx", status="skipped", detail=str(exc))
        logger.warning("%s -- dnsx skipped for %s, assuming it may resolve", exc, host)
        return True
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=host, tool_name="dnsx", status="failed", detail=str(exc))
        logger.error("dnsx failed for %s: %s -- assuming it may resolve", host, exc)
        return True


def _run_finding_module(
    module_cls, target_value: str, target_raw: str, asset: AssetRow, db: Database, config: dict,
    evidence: EvidenceStore,
) -> int:
    """Generic run/parse/persist/log cycle for a Tier 1 module that takes
    one string target and returns Findings -- the same try/except/
    finish_scan/save_raw/record_step shape every module in this file
    repeats, pulled out once so the newer additions below
    (cdncheck/dnstwist/git-exposure/tlsx-posture/dnsreaper/s3scanner)
    don't each re-copy it. Returns the number of findings persisted.
    """
    module = module_cls()
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name=module.name)
    try:
        raw = module.run(target_value, config)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=target_value, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, target_value)
        return 0
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=target_value, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, target_value, exc)
        return 0
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=target_value, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, target_value, exc)
        return 0

    try:
        findings = module.parse(raw, target_raw)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(
            tier=1, asset_value=target_value, tool_name=module.name, status="failed",
            detail=f"couldn't parse output: {exc}",
        )
        logger.error("%s produced unparseable output for %s: %s", module.name, target_value, exc)
        return 0

    db.finish_scan(scan_id, status="completed")
    raw_file = evidence.save_raw(tier=1, asset_value=target_value, tool_name=module.name, raw_output=raw)
    count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
    evidence.record_step(
        tier=1, asset_value=target_value, tool_name=module.name,
        status="completed", raw_file=raw_file, result_count=count,
    )
    if count:
        logger.warning("%s: %s found %d finding(s)", target_value, module.name, count)
    return count


def _run_subzy(asset: AssetRow, target_raw: str, db: Database, config: dict, evidence: EvidenceStore) -> None:
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="subzy")
    try:
        module = SubzyModule()
        raw = module.run(asset.value, config)
        findings = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=asset.value, tool_name="subzy", raw_output=raw)
        count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
        evidence.record_step(
            tier=1, asset_value=asset.value, tool_name="subzy",
            status="completed", raw_file=raw_file, result_count=count,
        )
        if count:
            logger.warning("%s: %d possible subdomain takeover finding(s)!", asset.value, count)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="subzy", status="skipped", detail=str(exc))
        logger.warning("%s -- subzy skipped for %s", exc, asset.value)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="subzy", status="failed", detail=str(exc))
        logger.error("subzy failed for %s: %s", asset.value, exc)


def _run_nmap_deep(
    asset: AssetRow, target_raw: str, db: Database, config: dict, port_assets, evidence: EvidenceStore
) -> None:
    # Chain step: the exact ports naabu (the previous step) found open are
    # read straight off its parsed result and handed to nmap -- nmap never
    # runs its own blind port discovery.
    ports = sorted({a.meta.get("port") for a in port_assets if a.meta.get("port")})
    if not ports:
        return
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="nmap")
    try:
        module = NmapDeepModule()
        raw = module.run(asset.value, config, ports=ports)
        findings = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=asset.value, tool_name="nmap", raw_output=raw)
        count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
        evidence.record_step(
            tier=1, asset_value=asset.value, tool_name="nmap", status="completed",
            raw_file=raw_file, result_count=count, detail=f"ports from naabu: {ports}",
        )
        logger.info("%s: nmap identified %d service(s) on %d open port(s)", asset.value, count, len(ports))
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="nmap", status="skipped", detail=str(exc))
        logger.warning("%s -- nmap skipped for %s", exc, asset.value)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="nmap", status="failed", detail=str(exc))
        logger.error("nmap failed for %s: %s", asset.value, exc)


def _run_live_url_modules(
    asset: AssetRow, live_url: str, target_raw: str, db: Database, config: dict, evidence: EvidenceStore
) -> None:
    """Modules that only make sense once we know a URL is actually
    serving HTTP: screenshot, tech fingerprint, WAF check, crawl, and a
    safe-mode nuclei scan. `live_url` itself is the chain step here -- it
    came out of httpx's result earlier in `run()` below.
    """
    # --- gowitness: screenshot ---------------------------------------------
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="gowitness")
    try:
        module = GowitnessModule()
        raw = module.run(live_url, config)
        shots = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="gowitness", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="gowitness",
            status="completed", raw_file=raw_file, result_count=len(shots),
        )
        if shots:
            logger.info("%s: screenshot saved to %s", live_url, shots[0].meta["screenshot_path"])
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="gowitness", status="skipped", detail=str(exc))
        logger.warning("%s -- gowitness skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="gowitness", status="failed", detail=str(exc))
        logger.error("gowitness failed for %s: %s", live_url, exc)

    # --- webanalyze: second tech-fingerprint source -------------------------
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="webanalyze")
    try:
        module = WebanalyzeModule()
        raw = module.run(live_url, config)
        results = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="webanalyze", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="webanalyze",
            status="completed", raw_file=raw_file, result_count=len(results),
        )
        if results:
            logger.info("%s: webanalyze detected %s", live_url, results[0].meta["tech"])
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="webanalyze", status="skipped", detail=str(exc))
        logger.warning("%s -- webanalyze skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="webanalyze", status="failed", detail=str(exc))
        logger.error("webanalyze failed for %s: %s", live_url, exc)

    # --- whatweb: a third tech-fingerprint source (log-only, same as ---------
    #     webanalyze above -- Asset.meta isn't persisted to the db today)
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="whatweb")
    try:
        module = WhatwebModule()
        raw = module.run(live_url, config)
        results = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="whatweb", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="whatweb",
            status="completed", raw_file=raw_file, result_count=len(results),
        )
        if results:
            logger.info("%s: whatweb detected %s", live_url, results[0].meta["tech"])
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="whatweb", status="skipped", detail=str(exc))
        logger.warning("%s -- whatweb skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="whatweb", status="failed", detail=str(exc))
        logger.error("whatweb failed for %s: %s", live_url, exc)

    # --- git-exposure: is .git accidentally deployed? -------------------------
    _run_finding_module(GitExposureModule, live_url, target_raw, asset, db, config, evidence)

    # --- wafw00f: WAF detection ---------------------------------------------
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="wafw00f")
    try:
        module = Wafw00fModule()
        raw = module.run(live_url, config)
        findings = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="wafw00f", raw_output=raw)
        count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="wafw00f",
            status="completed", raw_file=raw_file, result_count=count,
        )
        if count:
            logger.info("%s: %s", live_url, findings[0].title)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="wafw00f", status="skipped", detail=str(exc))
        logger.warning("%s -- wafw00f skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="wafw00f", status="failed", detail=str(exc))
        logger.error("wafw00f failed for %s: %s", live_url, exc)

    # --- katana: crawl for more endpoints -----------------------------------
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="katana")
    try:
        module = KatanaModule()
        raw = module.run(live_url, config)
        endpoints = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        for ep in endpoints:
            db.add_asset(asset.target_id, "endpoint", ep.value, discovered_by="katana")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="katana", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="katana",
            status="completed", raw_file=raw_file, result_count=len(endpoints),
        )
        if endpoints:
            logger.info("%s: katana crawled %d endpoint(s)", live_url, len(endpoints))
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="katana", status="skipped", detail=str(exc))
        logger.warning("%s -- katana skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="katana", status="failed", detail=str(exc))
        logger.error("katana failed for %s: %s", live_url, exc)

    # --- nuclei: safe-mode template scan ------------------------------------
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="nuclei")
    try:
        module = NucleiModule()
        raw = module.run(live_url, config)
        findings = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=1, asset_value=live_url, tool_name="nuclei", raw_output=raw)
        count = _persist_findings(db, asset.id, scan_id, findings, raw_file)
        evidence.record_step(
            tier=1, asset_value=live_url, tool_name="nuclei",
            status="completed", raw_file=raw_file, result_count=count,
        )
        if count:
            logger.info("%s: nuclei (safe mode) found %d finding(s)", live_url, count)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="nuclei", status="skipped", detail=str(exc))
        logger.warning("%s -- nuclei skipped for %s", exc, live_url)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=live_url, tool_name="nuclei", status="failed", detail=str(exc))
        logger.error("nuclei failed for %s: %s", live_url, exc)


def run(
    asset: AssetRow,
    target_raw: str,
    guard: ScopeGuard,
    db: Database,
    config: dict,
    evidence: EvidenceStore,
) -> dict:
    """Run the full Tier 1 chain against a single in-scope asset (a bare
    domain/subdomain, e.g. 'app.example.com'). Returns a small summary
    dict the orchestrator can log; persists results to the database as it
    goes, and every tool call's raw output + a step record goes to
    `evidence` (see core/evidence_store.py and the module docstring above
    for the full output/steps-log layout).
    """
    try:
        guard.assert_allowed(asset.value, tier=1, raw_target=target_raw)
    except ScopeViolation as exc:
        logger.warning("Tier 1 skipped for %s: %s", asset.value, exc)
        return {"live": False, "open_ports": 0, "skipped": "out_of_scope"}

    summary = {"live": False, "open_ports": 0}

    resolved = _check_resolves(asset.value, target_raw, db, asset.target_id, config, evidence)
    if not resolved:
        logger.info("%s: no DNS record -- skipping the rest of Tier 1 for this asset", asset.value)
        summary["resolved"] = False
        return summary
    summary["resolved"] = True

    # --- httpx: is it alive, and what's running on it? ---------------------
    live_url: str | None = None
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="httpx")
    try:
        module = HttpxModule()
        raw = module.run(asset.value, config)
        live_assets = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        for live_asset in live_assets:
            db.add_asset(asset.target_id, "url", live_asset.value, discovered_by="httpx")
            summary["live"] = True
            if live_url is None:
                live_url = live_asset.value
            logger.info(
                "%s is live: %s [%s] tech=%s",
                asset.value, live_asset.value,
                live_asset.meta.get("status_code"), live_asset.meta.get("tech"),
            )
        raw_file = evidence.save_raw(tier=1, asset_value=asset.value, tool_name="httpx", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=asset.value, tool_name="httpx",
            status="completed", raw_file=raw_file, result_count=len(live_assets),
        )
        if not live_assets:
            logger.info("%s: no response from httpx (likely dead/filtered)", asset.value)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="httpx", status="skipped", detail=str(exc))
        logger.warning("%s -- httpx probe skipped for %s", exc, asset.value)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="httpx", status="failed", detail=str(exc))
        logger.error("httpx failed for %s: %s", asset.value, exc)

    # --- naabu: what ports are open? ---------------------------------------
    port_assets = []
    scan_id = db.start_scan(asset.target_id, tier=1, tool_name="naabu")
    try:
        module = NaabuModule()
        raw = module.run(asset.value, config)
        port_assets = module.parse(raw, target_raw)
        db.finish_scan(scan_id, status="completed")
        summary["open_ports"] = len(port_assets)
        for port_asset in port_assets:
            db.add_asset(asset.target_id, "ip", port_asset.value, discovered_by="naabu")
        raw_file = evidence.save_raw(tier=1, asset_value=asset.value, tool_name="naabu", raw_output=raw)
        evidence.record_step(
            tier=1, asset_value=asset.value, tool_name="naabu",
            status="completed", raw_file=raw_file, result_count=len(port_assets),
        )
        if port_assets:
            logger.info("%s: %d open port(s) -- %s", asset.value, len(port_assets),
                        ", ".join(a.value for a in port_assets))
        else:
            logger.debug("%s: no open ports (or no DNS record)", asset.value)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="naabu", status="skipped", detail=str(exc))
        logger.warning("%s -- naabu port scan skipped for %s", exc, asset.value)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=1, asset_value=asset.value, tool_name="naabu", status="failed", detail=str(exc))
        logger.error("naabu failed for %s: %s", asset.value, exc)

    # --- nmap: targeted service detection on naabu's open ports -------------
    _run_nmap_deep(asset, target_raw, db, config, port_assets, evidence)

    # --- subzy / dnsreaper: subdomain takeover check (two independent ------
    #     fingerprint databases against the same dangling-CNAME question)
    _run_subzy(asset, target_raw, db, config, evidence)
    _run_finding_module(DnsReaperModule, asset.value, target_raw, asset, db, config, evidence)

    # --- cdncheck: is this host behind a CDN/WAF/cloud LB? -------------------
    _run_finding_module(CdncheckModule, asset.value, target_raw, asset, db, config, evidence)

    # --- tlsx (posture mode): expired cert / deprecated TLS / weak cipher ---
    _run_finding_module(TlsxPostureModule, asset.value, target_raw, asset, db, config, evidence)

    # --- live-URL-only modules: screenshot, tech, WAF, crawl, safe scan -----
    if live_url:
        _run_live_url_modules(asset, live_url, target_raw, db, config, evidence)
        # Tier 2 fuzzes this exact URL next -- handing it back in the
        # summary saves the orchestrator from re-deriving "what was the
        # live URL for this asset" from the db.
        summary["live_url"] = live_url

    return summary

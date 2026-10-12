"""
Tier 0 -- Passive recon. Runs once per root target. No traffic is sent to
the target itself.

Wires together every passive subdomain-enumeration source (subfinder,
assetfinder, github-subdomains, gitlab-subdomains, chaos, cero, amass,
tlsx), merges and dedupes their results, runs gau for historical/archived
URLs (stored for recon value, not fanned out to Tier 1+), runs asnmap
(ASN -> CIDR ranges) and cloud_enum (cloud storage bucket candidates) as
IP_RANGE/BUCKET assets, runs gitdorker (GitHub code-search dorking) for
possible leaked-secret Findings, and scope-filters everything before
persisting.

Secrets scanning (trufflehog, gitleaks) and scope-ingestion tools
(bbscope, Hacker-Scoper) are real, tested modules too (see
modules/recon/), but operate on repo URLs / program handles rather than
per-target domains, so they aren't part of this per-target loop -- see
each module's own docstring for how they fit into the workflow.
"""

from __future__ import annotations

import logging

from core.evidence_store import EvidenceStore
from core.scope_guard import ScopeGuard
from core.utils import normalize_domain
from db.models import AssetRow, Database
from modules.base import ToolError, ToolNotInstalled
from modules.recon.amass import AmassModule
from modules.recon.assetfinder import AssetfinderModule
from modules.recon.asnmap import AsnmapModule
from modules.recon.cero import CeroModule
from modules.recon.chaos import ChaosModule
from modules.recon.cloud_enum import CloudEnumModule
from modules.recon.gau import GauModule
from modules.recon.github_subdomains import GithubSubdomainsModule
from modules.recon.gitdorker import GitDorkerModule
from modules.recon.gitlab_subdomains import GitlabSubdomainsModule
from modules.recon.subfinder import SubfinderModule
from modules.recon.tlsx import TlsxModule

logger = logging.getLogger("scorpion.tier0")

# Every passive subdomain-enum source, run in sequence against the root
# domain. Order doesn't matter -- results are merged and deduped by
# hostname before anything downstream sees them.
SUBDOMAIN_SOURCES = [
    SubfinderModule,
    AssetfinderModule,
    GithubSubdomainsModule,
    GitlabSubdomainsModule,
    ChaosModule,
    CeroModule,
    AmassModule,
    TlsxModule,
]

# Sources that don't produce bare-hostname Assets -- each has its own
# result shape (IP_RANGE assets, BUCKET assets, Findings) and its own
# persistence step below, same "one bad source never blocks the rest"
# contract as SUBDOMAIN_SOURCES.
ASSET_SOURCES = [
    ("ip_range", AsnmapModule),
    ("bucket", CloudEnumModule),
]
FINDING_SOURCES = [GitDorkerModule]


def _run_source(
    module_cls, root_domain: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore
) -> list[str]:
    """Run one subdomain-enum module, recording its scan row plus a raw
    output file and a step record, and return the hostnames it found.
    Any failure (missing tool, missing API token, tool crash) is caught
    here and logged -- one bad source should never take down the rest of
    Tier 0.
    """
    module = module_cls()
    scan_id = db.start_scan(target_id, tier=0, tool_name=module.name)
    try:
        raw = module.run(root_domain, config)
        assets = module.parse(raw, root_domain)
        db.finish_scan(scan_id, status="completed")
        raw_file = evidence.save_raw(tier=0, asset_value=root_domain, tool_name=module.name, raw_output=raw)
        evidence.record_step(
            tier=0, asset_value=root_domain, tool_name=module.name,
            status="completed", raw_file=raw_file, result_count=len(assets),
        )
        logger.info("%s found %d candidate(s) for %s", module.name, len(assets), root_domain)
        return [a.value for a in assets if not a.meta.get("wildcard")]
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, root_domain)
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, root_domain, exc)
    except Exception as exc:  # noqa: BLE001 -- a broken source shouldn't kill the rest of Tier 0
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, root_domain, exc)
    return []


def _run_gau(root_domain: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore) -> int:
    """Run gau (archived URLs) and persist results as ENDPOINT assets.
    These aren't fanned out to Tier 1+ -- they're recon value for later
    (interesting old endpoints, parameters, file extensions), stored
    alongside the subdomain assets. Returns the count stored.
    """
    module = GauModule()
    scan_id = db.start_scan(target_id, tier=0, tool_name="gau")
    try:
        raw = module.run(root_domain, config)
        endpoints = module.parse(raw, root_domain)
        db.finish_scan(scan_id, status="completed")
        for ep in endpoints:
            db.add_asset(target_id, "endpoint", ep.value, discovered_by=ep.discovered_by)
        raw_file = evidence.save_raw(tier=0, asset_value=root_domain, tool_name="gau", raw_output=raw)
        evidence.record_step(
            tier=0, asset_value=root_domain, tool_name="gau",
            status="completed", raw_file=raw_file, result_count=len(endpoints),
        )
        logger.info("gau found %d archived URL(s) for %s", len(endpoints), root_domain)
        return len(endpoints)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name="gau", status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, root_domain)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name="gau", status="failed", detail=str(exc))
        logger.error("gau failed for %s: %s", root_domain, exc)
    return 0


def _run_asset_source(
    asset_type: str, module_cls, root_domain: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Same shape as _run_gau, generalized for ASSET_SOURCES -- a module
    that returns Assets of some non-subdomain type (IP_RANGE from asnmap,
    BUCKET from cloud_enum), persisted directly rather than merged into
    the subdomain fan-out list.
    """
    module = module_cls()
    scan_id = db.start_scan(target_id, tier=0, tool_name=module.name)
    try:
        raw = module.run(root_domain, config)
        found = module.parse(raw, root_domain)
        db.finish_scan(scan_id, status="completed")
        for item in found:
            db.add_asset(target_id, asset_type, item.value, discovered_by=item.discovered_by)
        raw_file = evidence.save_raw(tier=0, asset_value=root_domain, tool_name=module.name, raw_output=raw)
        evidence.record_step(
            tier=0, asset_value=root_domain, tool_name=module.name,
            status="completed", raw_file=raw_file, result_count=len(found),
        )
        if found:
            logger.info("%s found %d %s(s) for %s", module.name, len(found), asset_type, root_domain)
        return len(found)
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, root_domain)
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, root_domain, exc)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, root_domain, exc)
    return 0


def _run_finding_source(
    module_cls, root_domain: str, target_id: int, db: Database, config: dict, evidence: EvidenceStore
) -> int:
    """Same shape again, for FINDING_SOURCES (gitdorker) -- a module that
    returns Findings tied to the root domain itself rather than to any
    one asset, persisted against a synthetic "domain" asset row.
    """
    module = module_cls()
    scan_id = db.start_scan(target_id, tier=0, tool_name=module.name)
    try:
        raw = module.run(root_domain, config)
        findings = module.parse(raw, root_domain)
        db.finish_scan(scan_id, status="completed")
        domain_asset = db.add_asset(target_id, "domain", root_domain, discovered_by="seed")
        raw_file = evidence.save_raw(tier=0, asset_value=root_domain, tool_name=module.name, raw_output=raw)
        count = 0
        for finding in findings:
            finding_id = db.add_finding(
                domain_asset.id, title=finding.title, severity=finding.severity.value,
                description=finding.description, tier=finding.tier.value,
                scan_id=scan_id, confirmed=finding.confirmed,
            )
            if raw_file:
                db.add_evidence(finding_id, "raw_output", raw_file)
            count += 1
        evidence.record_step(
            tier=0, asset_value=root_domain, tool_name=module.name,
            status="completed", raw_file=raw_file, result_count=count,
        )
        if count:
            logger.warning("%s: %s found %d finding(s)", root_domain, module.name, count)
        return count
    except ToolNotInstalled as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.warning("%s -- skipped for %s", exc, root_domain)
    except ToolError as exc:
        db.finish_scan(scan_id, status="skipped")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="skipped", detail=str(exc))
        logger.info("%s -- skipped for %s (%s)", module.name, root_domain, exc)
    except Exception as exc:  # noqa: BLE001
        db.finish_scan(scan_id, status="failed")
        evidence.record_step(tier=0, asset_value=root_domain, tool_name=module.name, status="failed", detail=str(exc))
        logger.error("%s failed for %s: %s", module.name, root_domain, exc)
    return 0


def run(
    target_raw: str,
    target_id: int,
    guard: ScopeGuard,
    db: Database,
    config: dict,
    evidence: EvidenceStore,
) -> list[AssetRow]:
    """Discover subdomains for `target_raw` from every configured passive
    source, filter them through scope, and persist the allowed ones
    (including the root domain itself) as assets. Returns the list of
    in-scope AssetRows that Tier 1+ should fan out over.

    `evidence` gets each source's raw output saved to its own file, plus
    a step record for every source run -- see core/evidence_store.py.
    """
    root_domain = normalize_domain(target_raw)
    discovered_hosts: set[str] = set()

    for module_cls in SUBDOMAIN_SOURCES:
        discovered_hosts.update(_run_source(module_cls, root_domain, target_id, db, config, evidence))

    _run_gau(root_domain, target_id, db, config, evidence)

    for asset_type, module_cls in ASSET_SOURCES:
        _run_asset_source(asset_type, module_cls, root_domain, target_id, db, config, evidence)

    for module_cls in FINDING_SOURCES:
        _run_finding_source(module_cls, root_domain, target_id, db, config, evidence)

    # Always consider the root domain itself, even if every source found
    # nothing or none of them are installed -- it's the one host we're
    # certain about.
    candidates = {root_domain, *discovered_hosts}

    allowed_assets: list[AssetRow] = []
    for host in sorted(candidates):
        if not guard.is_allowed(host, tier=1, raw_target=target_raw):
            logger.debug("dropping %s -- not in scope for Tier 1+", host)
            continue
        asset_type = "domain" if host == root_domain else "subdomain"
        discovered_by = "seed" if host == root_domain else "tier0_merged"
        row = db.add_asset(target_id, asset_type, host, discovered_by=discovered_by)
        allowed_assets.append(row)

    logger.info(
        "%s: %d/%d candidates in scope (from %d source(s))",
        root_domain, len(allowed_assets), len(candidates), len(SUBDOMAIN_SOURCES),
    )
    return allowed_assets

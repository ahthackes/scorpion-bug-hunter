"""
The main loop: reads targets.txt, and for each target runs the tiered
pipeline. Tier 0 (passive recon + subdomain fan-out), Tier 1 (active
recon), and Tier 2 (both batches -- parameter/content discovery plus
vuln-class scanning) are implemented, followed by report generation
(reports/generator.py), which writes report.md/.html/.json into the
target's evidence folder once every tier has run. Tier 3 (exploitation)
is wired in as an explicit not-yet-implemented stop (only reached at all
when --enable-tier3 is passed) so the pipeline is honest about what it
actually does today rather than silently no-opping.
"""

from __future__ import annotations

import logging

import yaml

from core.evidence_store import EvidenceStore
from core.pipeline import tier0_passive, tier1_active, tier2_fuzzing
from core.scope_guard import ScopeGuard
from core.utils import load_targets
from db.models import Database
from reports import generator as report_generator

logger = logging.getLogger("scorpion.orchestrator")


class NotImplementedTier(Exception):
    """Raised (and caught, logged) when a tier is reached that has no real
    implementation yet. Distinct from a tool/runtime failure -- this means
    "we haven't built this part," not "something broke."
    """


class Orchestrator:
    def __init__(self, config_path: str = "config/settings.yaml", db_path: str = "db/scorpion.sqlite"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f) or {}
        self.db = Database(db_path)
        scope_enforce = self.config.get("scope", {}).get("enforce", True)
        self.guard = ScopeGuard(
            scope_dir="targets/scope",
            global_rules_path="config/scope_rules.yaml",
            enforce=scope_enforce,
        )
        if not scope_enforce:
            logger.warning(
                "Scope enforcement is DISABLED (config.scope.enforce: false) -- "
                "every host found in targets.txt will be scanned with no scope "
                "check. This is for testing only; re-enable before scanning a "
                "real bug bounty program."
            )

    def run(self, targets_file: str, enable_tier3: bool = False) -> None:
        targets = load_targets(targets_file)
        if not targets:
            logger.warning("No targets found in %s", targets_file)
            return
        logger.info("Loaded %d target(s) from %s", len(targets), targets_file)

        for raw_target in targets:
            self._run_one_target(raw_target, enable_tier3)

        self.db.close()

    def _run_one_target(self, raw_target: str, enable_tier3: bool) -> None:
        logger.info("=== Starting %s ===", raw_target)
        target = self.db.get_or_create_target(raw_target)

        if not self.guard.is_allowed(raw_target, tier=0, raw_target=raw_target):
            logger.error("%s is not in scope -- skipping entirely", raw_target)
            self.db.set_target_status(target.id, "out_of_scope")
            return

        self.db.set_target_status(target.id, "running")

        # Every tool invocation against this target, from here on, gets its
        # raw output saved to its own file and a line in the steps log --
        # see core/evidence_store.py. One store (one output/<target>/<run_id>/
        # folder) per target per run.
        evidence = EvidenceStore(base_dir="output", target_raw=raw_target)
        logger.info("%s: raw tool output + step log -> %s", raw_target, evidence.root)

        # Tier 0: passive recon + subdomain discovery, filtered through scope
        assets = tier0_passive.run(raw_target, target.id, self.guard, self.db, self.config, evidence)

        # Tier 1's own active brute-force step (puredns/massdns) runs once
        # per root target too, before the per-asset fan-out -- same shape
        # as Tier 0's sources, just active instead of passive. New hosts it
        # resolves get folded into the same fan-out list (deduped by value,
        # since Tier 0's passive sources may have already found some of
        # them).
        known_values = {a.value for a in assets}
        brute_forced = tier1_active.expand_subdomains(
            raw_target, target.id, self.guard, self.db, self.config, evidence
        )
        for row in brute_forced:
            if row.value not in known_values:
                assets.append(row)
                known_values.add(row.value)

        # Bulk-resolve the full candidate batch with shuffledns (extra
        # coverage context, not a gate -- see bulk_resolve()'s docstring),
        # check for lookalike/phishing domains (dnstwist), and validate any
        # cloud-storage bucket candidates Tier 0's cloud_enum turned up
        # (s3scanner) -- all three are once-per-root-target steps, same
        # shape as puredns above, run before the per-asset fan-out.
        tier1_active.bulk_resolve(raw_target, target.id, sorted(known_values), self.db, self.config, evidence)
        tier1_active.check_typosquats(raw_target, target.id, self.db, self.config, evidence)
        tier1_active.scan_buckets(raw_target, target.id, self.db, self.config, evidence)

        logger.info("%s: %d in-scope asset(s) to process", raw_target, len(assets))

        # Tier 1: fan out across every discovered asset. Keep each asset's
        # live URL (if any) around -- Tier 2 needs it and shouldn't have to
        # re-derive it from the db.
        live_count = 0
        live_urls: dict[int, str] = {}
        for asset in assets:
            result = tier1_active.run(asset, raw_target, self.guard, self.db, self.config, evidence)
            if result.get("live"):
                live_count += 1
            if result.get("live_url"):
                live_urls[asset.id] = result["live_url"]

        # Tier 2: fuzzing/detection (batch 1 -- parameter + content
        # discovery: arjun, x8, ffuf, feroxbuster). Only runs against
        # assets Tier 1 actually found a live URL for.
        tier2_new_endpoints = 0
        for asset in assets:
            live_url = live_urls.get(asset.id)
            if not live_url:
                logger.debug("  [%s] Tier 2 skipped -- no live URL", asset.value)
                continue
            result = tier2_fuzzing.run(asset, live_url, raw_target, self.guard, self.db, self.config, evidence)
            tier2_new_endpoints += result.get("new_endpoints", 0)

        # Tier 3: not implemented yet -- logged plainly rather than
        # pretending the scan is complete.
        if enable_tier3:
            for asset in assets:
                logger.info("  [%s] Tier 3 exploitation -- not implemented yet", asset.value)
                # TODO: core.pipeline.tier3_exploit.run(asset, raw_target, self.guard, self.db, self.config, confirm_callback)

        # Report generation: turns everything just persisted into
        # report.md/.html/.json, written into this run's own evidence
        # folder so the report sits right next to the raw output and
        # steps log that back it.
        try:
            report_paths = report_generator.build(target.id, self.db, evidence_root=evidence.root)
            logger.info("%s: report written -> %s", raw_target, report_paths["html"])
        except Exception as exc:  # noqa: BLE001
            # A report-generation failure shouldn't erase a completed
            # scan's results -- the db rows and raw evidence are still
            # there either way, so this is logged, not raised.
            logger.error("%s: report generation failed: %s", raw_target, exc)

        logger.info(
            "=== Finished %s (%d assets discovered, %d live, %d new Tier 2 endpoint(s)) ===",
            raw_target, len(assets), live_count, tier2_new_endpoints,
        )
        self.db.set_target_status(target.id, "complete")

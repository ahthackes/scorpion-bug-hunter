"""
Builds a comprehensive per-target report from the normalized db rows --
db.models.FindingDetail/ScanRow/AssetRow -- never from raw tool output
directly, though every finding that has a linked evidence row points at
the exact raw-output file that backs it, so a reviewer can go verify it
by hand (see core/evidence_store.py and db.models.Database.add_evidence).

Three output files per run, written into the same output/<target>/<run_id>/
folder every other tier already writes raw/, steps.log and steps.jsonl
into (via EvidenceStore), so a report sits right next to the evidence
that backs it:

    report.md     -- the full human-readable report (Markdown)
    report.html   -- the same content, styled, for opening in a browser
    report.json   -- the same data as structured JSON, for feeding into
                      another tool (a dashboard, a ticket importer, etc.)

Usage (see cli.py for the --report flag that wires this in):

    from reports.generator import build
    paths = build(target_id, db, evidence_root=evidence.root)
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from db.models import Database, FindingDetail, ScanRow
from reports.remediation import suggest as suggest_remediation

logger = logging.getLogger("scorpion.reports")

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Severity rank for sorting -- sqlite would sort these alphabetically
# (critical, high, info, low, medium), which is wrong for a report, so
# findings are always re-sorted in Python before rendering.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, len(_SEVERITY_ORDER))


def _scan_duration_seconds(scan: ScanRow) -> float | None:
    if not scan.finished_at:
        return None
    try:
        started = datetime.fromisoformat(scan.started_at)
        finished = datetime.fromisoformat(scan.finished_at)
        return round((finished - started).total_seconds(), 2)
    except ValueError:
        return None


def _build_tool_coverage(scans: list[ScanRow]) -> list[dict]:
    """One row per tool: how many times it ran against this target, split
    by outcome, plus total time spent -- the report's "what actually ran"
    section, independent of whether anything was found.
    """
    by_tool: dict[str, dict] = {}
    for scan in scans:
        row = by_tool.setdefault(
            scan.tool_name,
            {"tool_name": scan.tool_name, "tier": scan.tier, "completed": 0, "skipped": 0,
             "failed": 0, "running": 0, "total_runs": 0, "total_seconds": 0.0},
        )
        row["total_runs"] += 1
        row[scan.status] = row.get(scan.status, 0) + 1
        duration = _scan_duration_seconds(scan)
        if duration is not None:
            row["total_seconds"] += duration
    return sorted(by_tool.values(), key=lambda r: (r["tier"], r["tool_name"]))


def _build_asset_inventory(db: Database, target_id: int) -> list[dict]:
    assets = db.list_assets(target_id)
    by_type: dict[str, list] = {}
    for asset in assets:
        by_type.setdefault(asset.type, []).append(asset)
    return [
        {"type": type_, "count": len(rows), "entries": sorted(a.value for a in rows)}
        for type_, rows in sorted(by_type.items())
    ]


def _severity_counts(findings: list[FindingDetail]) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _jinja_env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _render_markdown(context: dict) -> str:
    return _jinja_env().get_template("report.md.j2").render(**context)


def _render_html(context: dict) -> str:
    """Rendered independently from the same context dict as the Markdown
    report -- not a markdown-to-HTML conversion -- so this has no
    dependency on a markdown library and can use real semantic markup
    (tables, severity badges) via reports/templates/report.html.j2.
    """
    return _jinja_env().get_template("report.html.j2").render(**context)


def build(
    target_id: int,
    db: Database,
    evidence_root: str | Path,
    generated_by: str = "scorpion-bug-hunter",
) -> dict[str, str]:
    """Render report.md, report.html and report.json for one target into
    `evidence_root` (an EvidenceStore's .root -- output/<target>/<run_id>/).
    Returns the three output paths. Never raises for "no findings" --
    an empty/clean scan still gets a full report saying so; only an
    unknown target_id or a template failure raises.
    """
    target = db.get_target(target_id)
    if target is None:
        raise ValueError(f"no target with id={target_id}")

    out_dir = Path(evidence_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_findings = db.list_findings_detailed(target_id)
    findings = sorted(raw_findings, key=lambda f: (_severity_rank(f.severity), f.tier, f.title))
    for finding in findings:
        # Not persisted on FindingDetail -- computed fresh here so editing
        # reports/remediation.py doesn't require a db migration or a
        # re-scan to take effect on the next report build.
        finding.remediation = suggest_remediation(finding.title)  # type: ignore[attr-defined]

    scans = db.list_scans(target_id)
    assets = db.list_assets(target_id)

    severity_counts = _severity_counts(findings)
    confirmed_count = sum(1 for f in findings if f.confirmed)
    tool_coverage = _build_tool_coverage(scans)
    asset_inventory = _build_asset_inventory(db, target_id)
    generated_at = datetime.now(timezone.utc).isoformat()

    context = {
        "target": target,
        "generated_at": generated_at,
        "generated_by": generated_by,
        "findings": findings,
        "severity_counts": severity_counts,
        "confirmed_count": confirmed_count,
        "total_findings": len(findings),
        "asset_count": len(assets),
        "asset_inventory": asset_inventory,
        "tool_coverage": tool_coverage,
        "scan_count": len(scans),
    }

    markdown_text = _render_markdown(context)
    html_text = _render_html(context)
    json_payload = {
        "target": {"id": target.id, "raw_input": target.raw_input, "program_name": target.program_name,
                    "status": target.status},
        "generated_at": generated_at,
        "generated_by": generated_by,
        "summary": {
            "total_findings": len(findings),
            "confirmed_findings": confirmed_count,
            "severity_counts": severity_counts,
            "asset_count": len(assets),
            "scan_count": len(scans),
        },
        "assets": [asdict(a) for a in assets],
        "tool_coverage": tool_coverage,
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity, "description": f.description,
                "tier": f.tier, "confirmed": f.confirmed, "asset_type": f.asset_type,
                "asset_value": f.asset_value, "tool_name": f.tool_name, "scan_status": f.scan_status,
                "remediation": getattr(f, "remediation", ""),
                "evidence": [{"type": e.type, "file_path": e.file_path} for e in f.evidence],
            }
            for f in findings
        ],
    }

    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path = out_dir / "report.json"
    md_path.write_text(markdown_text)
    html_path.write_text(html_text)
    json_path.write_text(json.dumps(json_payload, indent=2))

    logger.info(
        "%s: report written -- %d finding(s) (%d confirmed) across %d asset(s) -> %s",
        target.raw_input, len(findings), confirmed_count, len(assets), out_dir,
    )
    return {"markdown": str(md_path), "html": str(html_path), "json": str(json_path)}

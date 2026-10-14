"""
Persistence layer for the shared findings schema.

Built on Python's stdlib `sqlite3` rather than SQLAlchemy for now -- this
keeps the tool runnable with zero extra dependencies while the pipeline
logic is still being built out. The table shapes below match the
architecture doc's data model exactly, so swapping in SQLAlchemy/Postgres
later (see requirements.txt) is a drop-in change to this one file; nothing
in core/ or modules/ touches sqlite3 directly, only this module.

Tables: targets, assets, scans, findings, evidence
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_input       TEXT NOT NULL UNIQUE,
    program_name    TEXT,
    scope_file_ref  TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    type            TEXT NOT NULL,
    value           TEXT NOT NULL,
    discovered_by   TEXT,
    discovered_at   TEXT NOT NULL,
    UNIQUE(target_id, type, value)
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    tier            INTEGER NOT NULL,
    tool_name       TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id        INTEGER NOT NULL REFERENCES assets(id),
    scan_id         INTEGER REFERENCES scans(id),
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    tier            INTEGER NOT NULL,
    confirmed       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id),
    type            TEXT NOT NULL,
    file_path       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_target_id ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_target_type ON assets(target_id, type);
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TargetRow:
    id: int
    raw_input: str
    program_name: str | None
    status: str


@dataclass
class AssetRow:
    id: int
    target_id: int
    type: str
    value: str
    discovered_by: str | None = None


@dataclass
class FindingRow:
    id: int
    asset_id: int
    severity: str
    title: str
    description: str
    tier: int
    confirmed: bool
    scan_id: int | None = None


@dataclass
class ScanRow:
    id: int
    target_id: int
    tier: int
    tool_name: str
    started_at: str
    finished_at: str | None
    status: str


@dataclass
class EvidenceRow:
    id: int
    finding_id: int
    type: str
    file_path: str


@dataclass
class FindingDetail:
    """A finding joined with the asset it was found on and the scan that
    produced it -- what reports/generator.py actually needs to render one
    finding section without re-querying the db per row. `evidence` is
    filled in separately (see Database.list_findings_detailed) since a
    finding can have more than one evidence row.
    """
    id: int
    title: str
    severity: str
    description: str
    tier: int
    confirmed: bool
    asset_type: str
    asset_value: str
    tool_name: str | None
    scan_status: str | None
    evidence: list[EvidenceRow] = field(default_factory=list)


class Database:
    """Thin wrapper around a sqlite3 connection. One instance per run is
    plenty; sqlite3 connections aren't shared across threads, so a
    multi-threaded scheduler (Phase 5) will need one connection per worker.
    """

    def __init__(self, path: str = "db/scorpion.sqlite"):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextmanager
    def cursor(self):
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            cur.close()

    def close(self) -> None:
        self.conn.close()

    # --- targets ---------------------------------------------------------

    def get_or_create_target(self, raw_input: str, program_name: str | None = None) -> TargetRow:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE raw_input = ?", (raw_input,))
            row = cur.fetchone()
            if row:
                return TargetRow(row["id"], row["raw_input"], row["program_name"], row["status"])
            cur.execute(
                "INSERT INTO targets (raw_input, program_name, status, created_at) VALUES (?, ?, ?, ?)",
                (raw_input, program_name, "pending", _now()),
            )
            return TargetRow(cur.lastrowid, raw_input, program_name, "pending")

    def set_target_status(self, target_id: int, status: str) -> None:
        with self.cursor() as cur:
            cur.execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))

    def get_target(self, target_id: int) -> TargetRow | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
            row = cur.fetchone()
            if not row:
                return None
            return TargetRow(row["id"], row["raw_input"], row["program_name"], row["status"])

    def get_target_by_raw_input(self, raw_input: str) -> TargetRow | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE raw_input = ?", (raw_input,))
            row = cur.fetchone()
            if not row:
                return None
            return TargetRow(row["id"], row["raw_input"], row["program_name"], row["status"])

    def list_targets(self) -> list[TargetRow]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM targets ORDER BY id")
            return [TargetRow(r["id"], r["raw_input"], r["program_name"], r["status"]) for r in cur.fetchall()]

    # --- assets ------------------------------------------------------------

    def add_asset(self, target_id: int, type_: str, value: str, discovered_by: str | None = None) -> AssetRow:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO assets (target_id, type, value, discovered_by, discovered_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(target_id, type, value) DO UPDATE SET discovered_by = excluded.discovered_by
                """,
                (target_id, type_, value, discovered_by, _now()),
            )
            cur.execute(
                "SELECT * FROM assets WHERE target_id = ? AND type = ? AND value = ?",
                (target_id, type_, value),
            )
            row = cur.fetchone()
            return AssetRow(row["id"], row["target_id"], row["type"], row["value"], row["discovered_by"])

    def list_assets(self, target_id: int) -> list[AssetRow]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM assets WHERE target_id = ?", (target_id,))
            return [
                AssetRow(r["id"], r["target_id"], r["type"], r["value"], r["discovered_by"])
                for r in cur.fetchall()
            ]

    def list_assets_by_type(self, target_id: int, type_: str) -> list[AssetRow]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM assets WHERE target_id = ? AND type = ?",
                (target_id, type_),
            )
            return [
                AssetRow(r["id"], r["target_id"], r["type"], r["value"], r["discovered_by"])
                for r in cur.fetchall()
            ]

    def list_asset_values_by_types(self, target_id: int, types: tuple[str, ...]) -> list[str]:
        if not types:
            return []
        placeholders = ",".join("?" for _ in types)
        with self.cursor() as cur:
            cur.execute(
                f"SELECT value FROM assets WHERE target_id = ? AND type IN ({placeholders})",
                (target_id, *types),
            )
            return [r["value"] for r in cur.fetchall()]

    # --- scans ---------------------------------------------------------------

    def start_scan(self, target_id: int, tier: int, tool_name: str) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (target_id, tier, tool_name, started_at, status) VALUES (?, ?, ?, ?, ?)",
                (target_id, tier, tool_name, _now(), "running"),
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, status: str = "completed") -> None:
        with self.cursor() as cur:
            cur.execute(
                "UPDATE scans SET finished_at = ?, status = ? WHERE id = ?",
                (_now(), status, scan_id),
            )

    def list_scans(self, target_id: int) -> list[ScanRow]:
        """Every tool invocation recorded against this target -- the
        report's "tool coverage" section (what ran, what was skipped/
        failed, how long each step took) comes straight from this.
        """
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY started_at", (target_id,)
            )
            return [
                ScanRow(
                    r["id"], r["target_id"], r["tier"], r["tool_name"],
                    r["started_at"], r["finished_at"], r["status"],
                )
                for r in cur.fetchall()
            ]

    # --- findings -------------------------------------------------------------

    def add_finding(
        self,
        asset_id: int,
        title: str,
        severity: str,
        description: str,
        tier: int,
        scan_id: int | None = None,
        confirmed: bool = False,
    ) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO findings (asset_id, scan_id, severity, title, description, tier, confirmed)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (asset_id, scan_id, severity, title, description, tier, int(confirmed)),
            )
            return cur.lastrowid

    def list_findings(self, target_id: int) -> list[FindingRow]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT f.* FROM findings f
                   JOIN assets a ON f.asset_id = a.id
                   WHERE a.target_id = ?""",
                (target_id,),
            )
            return [
                FindingRow(
                    r["id"], r["asset_id"], r["severity"], r["title"],
                    r["description"], r["tier"], bool(r["confirmed"]), r["scan_id"],
                )
                for r in cur.fetchall()
            ]

    def list_findings_detailed(self, target_id: int) -> list[FindingDetail]:
        """Everything reports/generator.py needs for one finding section:
        the finding itself, the asset it was found on, which tool/scan
        produced it, and every evidence row (raw-output file paths) linked
        to it -- in one query plus one evidence lookup, rather than N+1
        queries per finding from the template.
        """
        with self.cursor() as cur:
            cur.execute(
                """SELECT f.id, f.title, f.severity, f.description, f.tier, f.confirmed,
                          a.type AS asset_type, a.value AS asset_value,
                          s.tool_name AS tool_name, s.status AS scan_status
                   FROM findings f
                   JOIN assets a ON f.asset_id = a.id
                   LEFT JOIN scans s ON f.scan_id = s.id
                   WHERE a.target_id = ?
                   ORDER BY f.severity, f.tier""",
                (target_id,),
            )
            rows = cur.fetchall()
            cur.execute(
                """SELECT e.* FROM evidence e
                   JOIN findings f ON e.finding_id = f.id
                   JOIN assets a ON f.asset_id = a.id
                   WHERE a.target_id = ?""",
                (target_id,),
            )
            evidence_by_finding: dict[int, list[EvidenceRow]] = {}
            for r in cur.fetchall():
                evidence_by_finding.setdefault(r["finding_id"], []).append(
                    EvidenceRow(r["id"], r["finding_id"], r["type"], r["file_path"])
                )

        return [
            FindingDetail(
                id=r["id"],
                title=r["title"],
                severity=r["severity"],
                description=r["description"] or "",
                tier=r["tier"],
                confirmed=bool(r["confirmed"]),
                asset_type=r["asset_type"],
                asset_value=r["asset_value"],
                tool_name=r["tool_name"],
                scan_status=r["scan_status"],
                evidence=evidence_by_finding.get(r["id"], []),
            )
            for r in rows
        ]

    # --- evidence -------------------------------------------------------------

    def add_evidence(self, finding_id: int, type_: str, file_path: str) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO evidence (finding_id, type, file_path) VALUES (?, ?, ?)",
                (finding_id, type_, file_path),
            )
            return cur.lastrowid

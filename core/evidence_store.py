"""
Persists every tool invocation's raw output to its own file on disk, and
keeps a running "steps" record (one line per tool run, in order) so a
full scan can be audited or replayed without re-querying the database --
and so a later stage in the chain can read an earlier tool's exact raw
output back off disk if it needs to, instead of only trusting whatever
got parsed into the db.

Layout, one EvidenceStore per target per run:

    output/<target>/<run_id>/
        raw/
            tier0_example.com_subfinder.txt
            tier0_example.com_gau.txt
            tier1_app.example.com_dnsx.txt
            tier1_app.example.com_httpx.txt
            tier1_app.example.com_naabu.txt
            tier1_app.example.com_nmap.txt
            ...
        steps.log     -- human-readable, one line per step, in order
        steps.jsonl   -- same steps, one JSON object per line, for
                         anything downstream that wants to parse the
                         chain programmatically

`run_id` defaults to a UTC timestamp, so re-running against the same
target doesn't clobber a previous run's evidence -- every run gets its
own folder.

This is deliberately plain-file based (no new DB tables) -- the sqlite
`scans`/`findings` tables already record structured state; this store is
the raw, unparsed companion to that, kept simple so it's easy to `cat`,
`grep`, or hand to another tool while debugging a run on the actual
target machine.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from core.utils import normalize_domain

logger = logging.getLogger("scorpion.evidence")


def _slug(value: str) -> str:
    """Filesystem-safe version of a hostname/URL/anything for use in a
    filename -- keeps letters, digits, dots and dashes, collapses
    everything else (scheme separators, slashes, ports, query strings)
    into underscores.
    """
    slug = re.sub(r"[^a-zA-Z0-9.-]+", "_", value).strip("_")
    return slug or "target"


class EvidenceStore:
    """One instance per target per run. Created by the orchestrator and
    passed down through the pipeline stages, which call `save_raw()` and
    `record_step()` around every tool invocation.
    """

    def __init__(self, base_dir: str, target_raw: str, run_id: str | None = None):
        self.target_raw = target_raw
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target_slug = normalize_domain(target_raw).replace("*", "_") or _slug(target_raw)
        self.root = Path(base_dir) / target_slug / self.run_id
        self.raw_dir = self.root / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self._steps_log_path = self.root / "steps.log"
        self._steps_jsonl_path = self.root / "steps.jsonl"

    def _raw_path(self, tier: int, asset_value: str, tool_name: str) -> Path:
        filename = f"tier{tier}_{_slug(asset_value)}_{tool_name}.txt"
        return self.raw_dir / filename

    def save_raw(self, tier: int, asset_value: str, tool_name: str, raw_output: str) -> str:
        """Write one tool's raw output to its own file and return the
        path as a string (empty string if the write failed). Never
        raises -- a disk problem here should be logged, not crash the
        scan that's otherwise working fine.
        """
        path = self._raw_path(tier, asset_value, tool_name)
        try:
            path.write_text(raw_output or "")
        except OSError as exc:
            logger.warning("couldn't write raw output to %s: %s", path, exc)
            return ""
        return str(path)

    def load_raw(self, tier: int, asset_value: str, tool_name: str) -> str | None:
        """Read back a previously saved raw file -- e.g. so a later tool
        in the chain, or a human re-inspecting a run, can see exactly
        what an earlier tool produced without re-running it. Returns
        None if nothing was ever saved for that tier/asset/tool.
        """
        path = self._raw_path(tier, asset_value, tool_name)
        if not path.exists():
            return None
        try:
            return path.read_text()
        except OSError as exc:
            logger.warning("couldn't read raw output from %s: %s", path, exc)
            return None

    def record_step(
        self,
        *,
        tier: int,
        asset_value: str,
        tool_name: str,
        status: str,
        detail: str = "",
        raw_file: str = "",
        result_count: int = 0,
    ) -> None:
        """Append one record of "this tool ran, against this asset, at
        this tier, with this outcome" to both the human-readable log and
        the machine-readable JSONL chain record. Called once per tool
        invocation, success or failure -- the steps file is the one
        place that shows the full chain in order, end to end.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "timestamp": timestamp,
            "tier": tier,
            "asset": asset_value,
            "tool": tool_name,
            "status": status,
            "result_count": result_count,
            "raw_file": raw_file,
            "detail": detail,
        }
        try:
            with open(self._steps_jsonl_path, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.warning("couldn't append to %s: %s", self._steps_jsonl_path, exc)

        line = f"[{timestamp}] tier{tier:<2} {tool_name:<12} {asset_value:<40} {status}"
        if result_count:
            line += f" ({result_count} result(s))"
        if raw_file:
            line += f" -> {raw_file}"
        if detail:
            line += f" -- {detail}"
        try:
            with open(self._steps_log_path, "a") as f:
                f.write(line + "\n")
        except OSError as exc:
            logger.warning("couldn't append to %s: %s", self._steps_log_path, exc)

"""Small shared helpers used by the orchestrator and pipeline stages."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def load_targets(path: str) -> list[str]:
    """Read targets.txt: one target per line, blank lines and lines
    starting with # are skipped.
    """
    targets: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def normalize_domain(raw_target: str) -> str:
    """Strip scheme/wildcard/path from a targets.txt line to get a bare
    domain suitable for tools like subfinder's -d flag.
    """
    value = raw_target.strip()
    if "://" in value:
        value = urlparse(value).hostname or value
    if value.startswith("*."):
        value = value[2:]
    return value.split("/")[0]


def ensure_output_dir(base_dir: str, target_raw: str, run_timestamp: str) -> Path:
    safe_name = normalize_domain(target_raw).replace("*", "_")
    out_dir = Path(base_dir) / safe_name / run_timestamp
    (out_dir / "raw").mkdir(parents=True, exist_ok=True)
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)
    return out_dir

"""
Scorpion Bug Hunter -- entry point.

Usage:
    python cli.py --targets targets/targets.txt
    python cli.py --targets targets/targets.txt --enable-tier3
    python cli.py --targets targets/targets.txt -v
"""

from __future__ import annotations

import logging

import click

from core.orchestrator import Orchestrator


@click.command()
@click.option(
    "--targets", "targets_file", required=True, type=click.Path(exists=True),
    help="Path to a targets.txt file (one domain/URL per line).",
)
@click.option(
    "--config", "config_path", default="config/settings.yaml", show_default=True,
    type=click.Path(exists=True), help="Path to the settings YAML file.",
)
@click.option(
    "--db", "db_path", default="db/scorpion.sqlite", show_default=True,
    help="Path to the sqlite database file.",
)
@click.option(
    "--enable-tier3", is_flag=True, default=False,
    help="Reach the Tier 3 stage in the pipeline. Not implemented -- it logs "
         "'not implemented' per asset and runs no exploitation tooling. See "
         "README's Safety section and core/pipeline/tier3_exploit.py.",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose (DEBUG) logging.")
def main(targets_file: str, config_path: str, db_path: str, enable_tier3: bool, verbose: bool) -> None:
    """Run the Scorpion Bug Hunter pipeline against every target in TARGETS_FILE."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    orchestrator = Orchestrator(config_path=config_path, db_path=db_path)
    orchestrator.run(targets_file, enable_tier3=enable_tier3)


if __name__ == "__main__":
    main()

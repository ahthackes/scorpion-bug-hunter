"""Tier pipeline stages. Each module exposes a run(asset, config) entry point
that the orchestrator calls; each stage is responsible for invoking the
relevant tool wrappers under modules/ and writing normalized results via
db.models.
"""

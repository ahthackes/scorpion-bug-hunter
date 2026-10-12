"""
Task queue / concurrency control.

Phase 1-2: a thin wrapper around asyncio so tool calls within a single
target's pipeline can run concurrently where safe (e.g. several Tier 1
recon tools against the same asset).

Phase 5+: swap in Celery + Redis if true multi-target parallelism
(--parallel N) is needed; the orchestrator should depend on this module's
interface, not on asyncio or Celery directly, so that swap stays contained
here.

TODO:
    - class Scheduler:
        - run_concurrent(self, coros: list[Awaitable], max_concurrency: int) -> list
        - run_sequential(self, callables: list[Callable]) -> list
"""

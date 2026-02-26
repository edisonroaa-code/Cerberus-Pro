#!/usr/bin/env python3
"""Standalone Cerberus job worker process."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

# Ensure imports work when running as a script: `python backend/job_worker.py`.
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (str(_SCRIPT_DIR), str(_PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ares_api import run_standalone_job_worker


logger = logging.getLogger(__name__)


async def _main() -> int:
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Windows event loop may not support POSIX signals.
            pass

    logger.info("Starting standalone job worker")
    await run_standalone_job_worker(stop_event=stop_event)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

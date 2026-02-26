"""Worker shim that pulls jobs from Redis and executes them.

This is a simple worker loop meant for local testing and development. Workers
should be run inside containers or managed instances in production.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

from backend.scheduler.redis_scheduler import RedisScheduler

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.scheduler = RedisScheduler(redis_url=redis_url)

    def handle_job(self, job: Dict[str, Any]) -> None:
        # Basic dispatch: job should include `type` and `payload`.
        job_type = job.get("type")
        payload = job.get("payload", {})
        logger.info("Handling job %s type=%s", job.get("id"), job_type)
        # Implement job handlers (scan, run_chain, sandbox_run) as needed.
        if job_type == "sandbox_run":
            from backend.offensiva.sandbox_runner import SandboxRunner

            sr = SandboxRunner()
            image = payload.get("image")
            cmd = payload.get("command")
            res = sr.run(image, cmd, timeout=payload.get("timeout"))
            logger.info("Sandbox result: %s", res)
            
            # Report result
            job_id = job.get("id")
            if job_id:
                self.scheduler.store_result(job_id, {"status": "completed", "result": str(res)})

        elif job_type == "scan_target":
            target = payload.get("target")
            logger.info(f"Starting scan for {target}")
            
            # Simulate scan execution (integrate with orchestrator here)
            # In a real scenario, this would call engine adapters
            import asyncio
            
            # This block is synchronous, but scans are async. 
            # Ideally Worker should run an event loop or use asyncio.run()
            
            # Placeholder result
            fake_findings = [
                {"type": "sql_injection", "severity": "high", "endpoint": "/login"}
            ]
            
            job_id = job.get("id")
            if job_id:
                self.scheduler.store_result(job_id, {"status": "completed", "findings": fake_findings})
                
        else:
            logger.warning("Unknown job type: %s", job_type)

    def run_loop(self, poll_interval: float = 1.0) -> None:
        logger.info("Worker started")
        while True:
            job = self.scheduler.dequeue(timeout=int(poll_interval))
            if job:
                try:
                    self.handle_job(job)
                except Exception as e:
                    logger.exception("Error handling job: %s", e)
            else:
                time.sleep(poll_interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    w = Worker()
    w.run_loop()

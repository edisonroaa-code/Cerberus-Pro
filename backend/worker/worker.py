"""Worker shim that pulls jobs from Redis and executes them.

This is a simple worker loop meant for local testing and development. Workers
should be run inside containers or managed instances in production.
"""
from __future__ import annotations

import json
import logging
import time
import asyncio
import threading
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

            job_id = job.get("id")
            if not target:
                if job_id:
                    self.scheduler.store_result(job_id, {"status": "failed", "error": "Missing target in scan_target payload"})
                return

            vectors = payload.get("vectors")
            if not isinstance(vectors, list) or not vectors:
                vectors = [{"endpoint": "/", "parameter": "id", "payloads": ["1", "1' OR '1'='1"]}]

            enabled_engines = payload.get("engines")
            if not isinstance(enabled_engines, list):
                enabled_engines = None

            try:
                findings = self._run_async(self._run_orchestrated_scan(str(target), vectors, enabled_engines))
                serialized = [
                    {
                        "type": str(getattr(f.type, "value", f.type)),
                        "endpoint": f.endpoint,
                        "parameter": f.parameter,
                        "payload": f.payload,
                        "confidence": float(f.confidence),
                        "severity": str(getattr(f.severity, "value", f.severity)),
                        "engine": f.engine,
                        "evidence": f.evidence,
                    }
                    for f in findings
                ]
                if job_id:
                    self.scheduler.store_result(
                        job_id,
                        {"status": "completed", "target": target, "findings": serialized, "count": len(serialized)},
                    )
            except Exception as e:
                logger.exception("scan_target job failed: %s", e)
                if job_id:
                    self.scheduler.store_result(job_id, {"status": "failed", "error": str(e)})
                
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

    async def _run_orchestrated_scan(self, target: str, vectors: list, enabled_engines: Any):
        # Import here to avoid heavy startup cost when worker handles non-scan tasks.
        import backend.engines  # noqa: F401
        from backend.engines.orchestrator import EngineOrchestrator

        orch = EngineOrchestrator(enabled_engines=enabled_engines)
        return await orch.scan_all(target, vectors)

    @staticmethod
    def _run_async(coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        if not loop.is_running():
            return loop.run_until_complete(coro)

        result_holder = {"value": None, "error": None}

        def _runner():
            try:
                result_holder["value"] = asyncio.run(coro)
            except Exception as e:  # pragma: no cover - defensive threading path
                result_holder["error"] = e

        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        t.join()
        if result_holder["error"] is not None:
            raise result_holder["error"]
        return result_holder["value"]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    w = Worker()
    w.run_loop()

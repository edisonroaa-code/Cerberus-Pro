"""Simple Redis-backed scheduler for job enqueueing/dequeueing.

This is a lightweight wrapper around redis lists to push/pop jobs as JSON.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

import redis


class RedisScheduler:
    def __init__(self, redis_url: str = "redis://localhost:6379/0", queue_name: str = "cerberus:jobs"):
        self._r = redis.from_url(redis_url)
        self.queue_name = queue_name

    def enqueue(self, job: Dict[str, Any]) -> None:
        self._r.rpush(self.queue_name, json.dumps(job))

    def dequeue(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        item = self._r.blpop(self.queue_name, timeout=timeout)
        if not item:
            return None
        _, raw = item
        return json.loads(raw)

    def queue_len(self) -> int:
        return self._r.llen(self.queue_name)

    def store_result(self, job_id: str, result: Dict[str, Any], ttl: int = 3600) -> None:
        """Store job result for retrieval."""
        key = f"cerberus:result:{job_id}"
        self._r.setex(key, ttl, json.dumps(result))

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job result/status."""
        key = f"cerberus:result:{job_id}"
        val = self._r.get(key)
        if not val:
            return None
        return json.loads(val)

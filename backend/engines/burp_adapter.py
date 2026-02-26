from __future__ import annotations

from typing import List, Dict

from .base import EngineAdapter, EngineConfig, Finding


class BurpAdapter(EngineAdapter):
    def __init__(self, config: EngineConfig):
        super().__init__(config)

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        # Burp integration placeholder: no-op for now.
        return []

    def get_status(self) -> Dict:
        return {
            "engine": self.config.engine_id,
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": 0,
            "errors": 0,
        }

    async def stop(self):
        return

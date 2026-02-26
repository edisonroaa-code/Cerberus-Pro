"""
Cerberus Pro v4 - Engine Orchestrator

Coordinates parallel execution of all vulnerability scanning engines.
Aggregates findings with deduplication and confidence scoring.
"""

import asyncio
import logging
from typing import List, Dict, Optional, Set
from datetime import datetime, timezone

from .base import (
    EngineAdapter,
    Finding,
    EngineConfig,
    get_engine,
    list_engines,
)
from ..core.waf_detective import fingerprint as waf_fingerprint
from ..offensiva.evasion_strategies import get_bypass_strategies, apply_strategies_to_engine
from ..core.chain_orchestrator_v2 import ChainOrchestratorV2

logger = logging.getLogger("cerberus.engines.orchestrator")


class EngineOrchestrator:
    """Master engine coordinator - runs all engines in parallel"""

    def __init__(self, enabled_engines: Optional[List[str]] = None):
        """
        Initialize orchestrator with optional engine whitelist.

        Args:
            enabled_engines: List of engine IDs to run (None = all)
        """
        self.enabled_engines = enabled_engines or []
        self.all_findings: List[Finding] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    async def scan_all(
        self, target: str, vectors: List[Dict]
    ) -> List[Finding]:
        """
        Execute all enabled engines in parallel.

        Args:
            target: Target URL or hostname
            vectors: List of parameter vectors to test

        Returns:
            Deduplicated findings sorted by confidence
        """
        self.start_time = datetime.now(timezone.utc)
        self.all_findings = []

        engines_to_run = []

        if self.enabled_engines:
            # Use whitelist
            for engine_id in self.enabled_engines:
                engine = get_engine(engine_id)
                if engine:
                    engines_to_run.append(engine)
                else:
                    logger.warning(f"Engine not found: {engine_id}")
        else:
            # Use all available
            for engine_id in list_engines():
                engine = get_engine(engine_id)
                if engine:
                    engines_to_run.append(engine)

        if not engines_to_run:
            logger.error("No engines available to run")
            self.end_time = datetime.now(timezone.utc)
            return []

        logger.info(f"Starting orchestrated scan with {len(engines_to_run)} engines")

        # Detect WAF/IDS and apply evasive strategies if found
        try:
            waf_info = await waf_fingerprint(target)
            if waf_info and waf_info.get("waf"):
                waf_name = waf_info.get("waf")
                logger.info(f"Detected WAF: {waf_name} - applying bypass strategies")
                strategies = get_bypass_strategies(waf_name)
                for engine in engines_to_run:
                    apply_strategies_to_engine(engine, strategies)
            else:
                logger.debug("No WAF detected or insufficient evidence")
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")

        # Run all engines in parallel
        tasks = [
            self._run_engine_safe(engine, target, vectors)
            for engine in engines_to_run
        ]

        results = await asyncio.gather(*tasks)

        # Aggregate results
        for engine_findings in results:
            if engine_findings:
                self.all_findings.extend(engine_findings)

        # Deduplicate
        deduplicated = self._deduplicate_findings(self.all_findings)

        # Sort by confidence (descending)
        deduplicated.sort(key=lambda f: f.confidence, reverse=True)

        self.end_time = datetime.now(timezone.utc)

        logger.info(
            f"Orchestrated scan complete: {len(self.all_findings)} findings -> "
            f"{len(deduplicated)} after dedup"
        )

        return deduplicated

    async def _run_engine_safe(
        self, engine: EngineAdapter, target: str, vectors: List[Dict]
    ) -> List[Finding]:
        """Safely execute single engine with error handling"""
        engine_id = engine.config.engine_id
        try:
            logger.debug(f"Engine {engine_id} scan starting")
            findings = await engine.scan(target, vectors)
            logger.info(f"Engine {engine_id}: {len(findings)} findings")
            return findings
        except asyncio.TimeoutError:
            logger.error(f"Engine {engine_id} timeout")
            return []
        except Exception as e:
            logger.error(f"Engine {engine_id} error: {e}")
            return []

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on dedup_key"""
        seen: Set[str] = set()
        deduplicated: List[Finding] = []

        for finding in findings:
            dedup_key = finding.dedup_key()
            if dedup_key not in seen:
                seen.add(dedup_key)
                deduplicated.append(finding)

        return deduplicated

    def get_status(self) -> Dict:
        """Get orchestrator status"""
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "orchestrator": "engine_orchestrator",
            "status": "ready",
            "enabled_engines": self.enabled_engines or "all",
            "total_findings": len(self.all_findings),
            "duration_ms": duration,
        }

    async def stop_all(self):
        """Stop all running engines"""
        logger.info("Stopping all engines")
        # Engines manage their own lifecycle

    async def run_chain_template(self, chain: dict, target: str, vectors: list) -> dict:
        """Integrate ChainOrchestratorV2: execute a chain template using registered engines.

        This method delegates step->engine mapping to ChainOrchestratorV2.run_chain_async
        to reuse the existing mapping logic.
        """
        co = ChainOrchestratorV2()
        # ensure templates are loaded (if chain is None, select_best_chain would load)
        return await co.run_chain_async(chain, target, vectors)


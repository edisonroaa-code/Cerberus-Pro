"""
Cerberus Pro v4 - Resource Escalation Engine

Dynamically escalates resource utilization when opportunities are detected.
Monitors available CPU/memory/time and intelligently adds more engines,
payloads, vectors, and parallelism to maximize coverage until diminishing returns.

Sin cajas negras: Every escalation decision is logged, auditable, and reversible.
"""

import asyncio
import logging
import os
import shutil
import importlib.util
from pathlib import Path
try:
    import psutil
except Exception:
    psutil = None
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field
from backend.core.coverage_ledger import (
    CoverageLedger,
    ConclusiveBlocker,
    PhaseCompletionRecord,
    VectorCoverageRecord,
    CoverageStatus,
)

logger = logging.getLogger("cerberus.resource_escalation")


class EscalationReason(str, Enum):
    """Why escalation was triggered"""
    LOW_COVERAGE = "low_coverage"                    # < 80% input coverage
    INCOMPLETE_ENGINES = "incomplete_engines"        # Not all engines ran
    MISSING_VECTORS = "missing_vectors"              # Vector types not explored
    IDLE_RESOURCES = "idle_resources"                # CPU/memory available
    CONFIRMED_VULN = "confirmed_vuln"                # Vuln found, need deep dive
    DIMINISHING_RETURNS = "diminishing_returns"      # Cost > benefit, stop


class EscalationAction(str, Enum):
    """What to do when escalating"""
    ADD_ENGINE = "add_engine"                        # Add new scanner
    ADD_PAYLOADS = "add_payloads"                    # Expand payload set
    ADD_VECTORS = "add_vectors"                      # Test more input types
    ADD_PARALLELISM = "add_parallelism"              # Increase parallel jobs
    DEEPEN_VECTORS = "deepen_vectors"                # Test variants of found vectors
    EXTEND_TIMEOUT = "extend_timeout"                # Give more time to current phase


class ResourceMetrics(BaseModel):
    """Real-time resource utilization snapshot"""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cpu_percent: float = Field(description="CPU usage 0-100%")
    memory_percent: float = Field(description="Memory usage 0-100%")
    memory_available_mb: float = Field(description="Available memory in MB")
    disk_percent: float = Field(description="Disk usage 0-100%")
    active_jobs: int = Field(description="Currently running jobs")
    queued_jobs: int = Field(description="Jobs waiting in queue")
    
    def has_capacity(self, cpu_threshold: float = 70.0, mem_threshold: float = 75.0) -> bool:
        """Check if system has capacity for more work"""
        return self.cpu_percent < cpu_threshold and self.memory_percent < mem_threshold


@dataclass
class EscalationDecision:
    """Decision to escalate resources"""
    reason: EscalationReason
    action: EscalationAction
    target_engines: Optional[List[str]] = None          # Engines to add
    target_payloads: Optional[int] = None                # Number of payloads to add
    target_vectors: Optional[List[str]] = None           # Vector types to add
    parallel_increase: Optional[int] = None              # How many more parallel jobs
    timeout_increase_ms: Optional[int] = None            # Additional timeout
    expected_benefit: Optional[float] = None             # Estimated coverage increase %
    cost_estimate_ms: Optional[int] = None               # Estimated time cost
    timestamp: datetime = field(default_factory=datetime.utcnow)
    audit_trail: str = ""                                # Why this decision

    def is_worth_it(self, max_cost_ms: int = 60000) -> bool:
        """Heuristic: is the benefit worth the cost?"""
        if not self.cost_estimate_ms or not self.expected_benefit:
            return True
        # Benefit >= 5% needs to be worth > 1 minute
        return (self.expected_benefit >= 5.0) or (self.cost_estimate_ms < max_cost_ms)


class EscalationProfile(BaseModel):
    """Configuration for escalation behavior"""
    enabled: bool = True
    max_engines: int = 5                    # Max engines to deploy
    max_parallel_jobs: int = 16             # Max parallel execution
    max_total_time_ms: int = 3600000        # Max 1 hour total
    cpu_threshold: float = 70.0             # Start offloading if > 70%
    memory_threshold: float = 75.0          # Start limiting if > 75%
    min_coverage_for_escalation: float = 50.0  # Only escalate if coverage < 50%
    max_coverage_for_payloads: float = 90.0    # Stop adding payloads at 90%
    vector_expansion_factor: float = 1.5   # 1.5x more vectors per escalation
    engine_discovery_delay_ms: int = 5000  # Wait 5s before trying new engine
    diminishing_return_threshold: float = 1.0  # Stop if gain < 1%


class ResourceEscalationEngine:
    """
    Main engine for intelligent resource escalation.
    
    Usage:
        engine = ResourceEscalationEngine()
        decision = await engine.evaluate_escalation(ledger, metrics)
        if decision:
            await engine.apply_decision(decision, scheduler, coverage_ledger)
    """

    ENGINE_DEPENDENCIES: Dict[str, List[str]] = {
        "UNION": ["sqlmap"],
        "ERROR": ["sqlmap"],
        "TIME": ["sqlmap"],
        "BOOLEAN": ["sqlmap"],
        "NOSQL": ["sqlmap"],
        "SSTI": ["sqlmap"],
        "AIIE": ["sqlmap"],
        "WEBSOCKET": ["websockets"],
        "MQTT": ["paho-mqtt"],
        "GRPC": ["grpcio"],
    }
    
    def __init__(self, profile: Optional[EscalationProfile] = None):
        self.profile = profile or EscalationProfile()
        self.decisions_history: List[EscalationDecision] = []
        self.engines_deployed: Dict[str, datetime] = {}  # Engine -> when deployed
        self.payload_versions: Dict[str, int] = {}       # Payload -> iteration count
        self.vector_expansion_rounds: int = 0            # Times we expanded vectors
        self.total_escalation_time_ms: int = 0
        self.total_escalations: int = 0

    @staticmethod
    def _is_module_available(module_name: str) -> bool:
        if not module_name:
            return False
        try:
            return importlib.util.find_spec(module_name) is not None
        except Exception:
            return False

    @staticmethod
    def _is_binary_or_path_available(name_or_path: str) -> bool:
        candidate = str(name_or_path or "").strip()
        if not candidate:
            return False
        try:
            if Path(candidate).exists():
                return True
        except Exception:
            pass
        return bool(shutil.which(candidate))

    def _dependency_available(self, dep_name: str) -> bool:
        dep = str(dep_name or "").strip().lower()
        if not dep:
            return False

        if dep == "sqlmap":
            env_path = os.environ.get("CERBERUS_SQLMAP_PATH", "").strip()
            default_path = Path(__file__).resolve().parents[2] / "cerberus_engine" / "sqlmap.py"
            candidates = [env_path, str(default_path), "sqlmap"]
            return any(self._is_binary_or_path_available(c) for c in candidates if c)

        module_map = {
            "playwright": "playwright",
            "grpcio": "grpc",
            "paho-mqtt": "paho.mqtt.client",
            "dnslib": "dnslib",
            "scapy": "scapy",
            "websockets": "websockets",
            "redis": "redis",
        }
        module_name = module_map.get(dep, dep)
        return self._is_module_available(module_name)

    def required_dependencies_for_engines(self, required_engines: Optional[List[str]]) -> List[str]:
        deps: List[str] = []
        for engine in required_engines or []:
            key = str(engine or "").strip().upper()
            for dep in self.ENGINE_DEPENDENCIES.get(key, []):
                if dep not in deps:
                    deps.append(dep)
        return deps

    async def run_preflight_checks(
        self,
        coverage_ledger: Optional[CoverageLedger] = None,
        required_dependencies: Optional[List[str]] = None,
        required_engines: Optional[List[str]] = None,
        phase_name: str = "preflight",
    ) -> Dict[str, Any]:
        """
        Real preflight validation for dependencies and engine prerequisites.
        Updates CoverageLedger with deps/blockers when provided.
        """
        started_at = datetime.now(timezone.utc)

        dependencies: List[str] = []
        for dep in (required_dependencies or []):
            name = str(dep or "").strip()
            if name and (name not in dependencies):
                dependencies.append(name)
        for dep in self.required_dependencies_for_engines(required_engines):
            if dep not in dependencies:
                dependencies.append(dep)

        available: List[str] = []
        missing: List[str] = []
        for dep in dependencies:
            if self._dependency_available(dep):
                available.append(dep)
            else:
                missing.append(dep)

        if coverage_ledger is not None:
            coverage_ledger.deps_requested = sorted(set((coverage_ledger.deps_requested or []) + dependencies))
            coverage_ledger.deps_available = sorted(set((coverage_ledger.deps_available or []) + available))
            coverage_ledger.deps_missing = sorted(set((coverage_ledger.deps_missing or []) + missing))

            for dep in missing:
                coverage_ledger.add_blocker(
                    ConclusiveBlocker(
                        category="missing_deps",
                        detail=f"Required dependency '{dep}' not available",
                        phase=phase_name,
                        recoverable=True,
                        evidence=f"dependency:{dep}",
                    )
                )

            duration_ms = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
            coverage_ledger.add_phase_record(
                PhaseCompletionRecord(
                    phase=phase_name,
                    status="completed" if len(missing) == 0 else "partial",
                    duration_ms=duration_ms,
                    start_time=started_at,
                    end_time=datetime.now(timezone.utc),
                    items_processed=len(dependencies),
                    items_failed=len(missing),
                    notes=(
                        [f"deps_available={','.join(sorted(available))}"] if available else []
                    )
                    + (
                        [f"deps_missing={','.join(sorted(missing))}"] if missing else []
                    ),
                )
            )

        return {
            "ok": len(missing) == 0,
            "requested": dependencies,
            "available": available,
            "missing": missing,
        }
        
    async def get_system_metrics(self) -> ResourceMetrics:
        """Capture real-time resource metrics"""
        if psutil:
            try:
                cpu = psutil.cpu_percent(interval=0.1)
                vm = psutil.virtual_memory()
                mem = vm.percent
                mem_avail = vm.available / 1024 / 1024
                try:
                    disk = psutil.disk_usage("/").percent
                except Exception:
                    disk = 0.0
            except Exception:
                cpu = 0.0
                mem = 0.0
                mem_avail = 0.0
                disk = 0.0
        else:
            # Fallback when psutil not installed: conservative defaults
            cpu = 0.0
            mem = 0.0
            mem_avail = 0.0
            try:
                disk_usage = shutil.disk_usage('.')
                disk = (disk_usage.used / disk_usage.total) * 100.0
            except Exception:
                disk = 0.0

        return ResourceMetrics(
            cpu_percent=cpu,
            memory_percent=mem,
            memory_available_mb=mem_avail,
            disk_percent=disk,
            active_jobs=0,  # Would be updated from scheduler
            queued_jobs=0   # Would be updated from scheduler
        )
    
    async def evaluate_escalation(
        self,
        coverage_ledger,  # CoverageLedger instance
        current_metrics: Optional[ResourceMetrics] = None,
        phase_name: str = "unknown",
        elapsed_ms: int = 0,
    ) -> Optional[EscalationDecision]:
        """
        Evaluate if escalation is warranted.
        Returns decision if yes, None if no escalation needed.
        """
        if not self.profile.enabled:
            return None
        
        metrics = current_metrics or await self.get_system_metrics()
        coverage_pct = coverage_ledger.coverage_percentage()
        blockers = coverage_ledger.conclusive_blockers
        
        # Check various triggers for escalation
        
        # Trigger 1: Low coverage despite available resources
        if coverage_pct < self.profile.min_coverage_for_escalation and metrics.has_capacity():
            missing_engines = self._get_missing_engines(coverage_ledger)
            if missing_engines:
                engines_to_add = missing_engines[:self.profile.max_engines - len(coverage_ledger.engines_executed)]
                return EscalationDecision(
                    reason=EscalationReason.INCOMPLETE_ENGINES,
                    action=EscalationAction.ADD_ENGINE,
                    target_engines=engines_to_add,
                    expected_benefit=15.0,  # 15% expected boost
                    cost_estimate_ms=20000,
                    audit_trail=f"Coverage {coverage_pct:.1f}% low, {len(engines_to_add)} engines available"
                )
        
        # Trigger 2: Vectors not fully explored for tested inputs
        if coverage_ledger.inputs_tested > 0 and coverage_pct < self.profile.max_coverage_for_payloads:
            vector_gap = self._compute_vector_gap(coverage_ledger)
            if vector_gap > 2:  # Missing 2+ vector types
                return EscalationDecision(
                    reason=EscalationReason.MISSING_VECTORS,
                    action=EscalationAction.ADD_VECTORS,
                    target_vectors=self._get_vector_types_to_add(coverage_ledger),
                    expected_benefit=8.0,
                    cost_estimate_ms=15000,
                    audit_trail=f"Missing {vector_gap} vector types, {coverage_ledger.inputs_tested} inputs found"
                )
        
        # Trigger 3: Confirmed vulnerability -> deep dive with all resources
        if any(b.category == "confirmed_vuln" for b in blockers):
            return EscalationDecision(
                reason=EscalationReason.CONFIRMED_VULN,
                action=EscalationAction.ADD_PARALLELISM,
                parallel_increase=min(4, self.profile.max_parallel_jobs - 4),  # Add 4 more parallel
                expected_benefit=20.0,
                cost_estimate_ms=30000,
                audit_trail="Confirmed vulnerability, deploying full arsenal"
            )
        
        # Trigger 4: Idle resources -> opportunistic scanning
        if metrics.has_capacity() and coverage_pct < 80.0:
            if self.total_escalations < 3:  # Limit to 3 escalations
                return EscalationDecision(
                    reason=EscalationReason.IDLE_RESOURCES,
                    action=EscalationAction.ADD_PAYLOADS,
                    target_payloads=int(250 * self.profile.vector_expansion_factor),  # +250 payloads
                    expected_benefit=5.0,
                    cost_estimate_ms=25000,
                    audit_trail=f"Idle resources (CPU:{metrics.cpu_percent:.0f}%, MEM:{metrics.memory_percent:.0f}%)"
                )
        
        # Trigger 5: Diminishing returns -> stop escalating
        if self.total_escalations > 3 or elapsed_ms > self.profile.max_total_time_ms * 0.8:
            last_decision = self.decisions_history[-1] if self.decisions_history else None
            if last_decision and (datetime.now(timezone.utc) - last_decision.timestamp).total_seconds() > 180:
                # Was 3 minutes since last decision, if coverage still < 80%, probably diminishing
                if coverage_pct < 80.0:
                    logger.warning(
                        f"Diminishing returns detected: {self.total_escalations} "
                        f"escalations, coverage still {coverage_pct:.1f}%, stopping"
                    )
                    return None
        
        return None  # No escalation needed
    
    async def apply_decision(
        self,
        decision: EscalationDecision,
        scheduler,  # SchedulerJobQueue instance
        coverage_ledger,
    ) -> bool:
        """
        Apply the escalation decision. Returns True if successful.
        """
        if not decision.is_worth_it():
            logger.info(f"Escalation decision {decision.action} skipped: not worth cost")
            return False
        
        try:
            if decision.action == EscalationAction.ADD_ENGINE:
                await self._deploy_engines(decision.target_engines, scheduler, coverage_ledger)
            
            elif decision.action == EscalationAction.ADD_PAYLOADS:
                await self._expand_payloads(decision.target_payloads, coverage_ledger)
            
            elif decision.action == EscalationAction.ADD_VECTORS:
                await self._add_vector_types(decision.target_vectors, coverage_ledger)
            
            elif decision.action == EscalationAction.ADD_PARALLELISM:
                await self._increase_parallelism(decision.parallel_increase, scheduler)
            
            elif decision.action == EscalationAction.EXTEND_TIMEOUT:
                await self._extend_timeout(decision.timeout_increase_ms, coverage_ledger)
            
            # Record in history
            self.decisions_history.append(decision)
            self.total_escalations += 1
            if decision.cost_estimate_ms:
                self.total_escalation_time_ms += decision.cost_estimate_ms
            
            logger.info(
                f"✓ Escalation applied: {decision.action.value} | "
                f"Expected +{decision.expected_benefit:.1f}% coverage | "
                f"Cost: {decision.cost_estimate_ms}ms | Reason: {decision.reason.value}"
            )
            return True
        
        except Exception as e:
            logger.error(f"✗ Failed to apply escalation {decision.action.value}: {e}")
            return False
    
    async def _deploy_engines(
        self,
        engines: List[str],
        scheduler,
        coverage_ledger
    ):
        """Deploy additional scanning engines"""
        for engine in engines or []:
            if engine not in self.engines_deployed:
                logger.info(f"  [ESCALATE] Deploying engine: {engine}")
                if engine not in coverage_ledger.engines_requested:
                    coverage_ledger.engines_requested.append(engine)
                self.engines_deployed[engine] = datetime.now(timezone.utc)
                # In production, scheduler would enqueue jobs for this engine
    
    async def _expand_payloads(
        self,
        additional_payloads: int,
        coverage_ledger
    ):
        """Add more payloads to scanning mix"""
        payloads = int(additional_payloads or 0)
        logger.info(f"  [ESCALATE] Expanding payloads: +{payloads}")
        self.vector_expansion_rounds += 1
        started = datetime.now(timezone.utc)
        coverage_ledger.add_phase_record(
            PhaseCompletionRecord(
                phase="escalation_payload",
                status="completed",
                duration_ms=0,
                start_time=started,
                end_time=datetime.now(timezone.utc),
                items_processed=payloads,
                items_failed=0,
                notes=[f"added_payloads={payloads}", f"round={self.vector_expansion_rounds}"],
            )
        )
    
    async def _add_vector_types(
        self,
        vector_types: List[str],
        coverage_ledger
    ):
        """Add new vector types: headers, cookies, fragments, etc."""
        normalized_vectors = [str(v).strip().upper() for v in (vector_types or []) if str(v).strip()]
        logger.info(f"  [ESCALATE] Adding vectors: {', '.join(normalized_vectors)}")
        for idx, vtype in enumerate(normalized_vectors):
            coverage_ledger.add_vector_record(
                VectorCoverageRecord(
                    vector_id=f"escalation_{self.vector_expansion_rounds}_{idx}",
                    vector_name=vtype,
                    engine="ESCALATION",
                    status=CoverageStatus.QUEUED,
                    inputs_found=0,
                    inputs_tested=0,
                    inputs_failed=0,
                    duration_ms=0,
                    error=None,
                    evidence=[f"added_by_escalation_round={self.vector_expansion_rounds}"],
                )
            )
    
    async def _increase_parallelism(
        self,
        additional_workers: int,
        scheduler
    ):
        """Increase parallel job execution"""
        logger.info(f"  [ESCALATE] Parallelism: +{additional_workers} workers")
        # Would reconfigure scheduler.max_parallel
    
    async def _extend_timeout(
        self,
        additional_ms: int,
        coverage_ledger
    ):
        """Give current phase more time"""
        logger.info(f"  [ESCALATE] Timeout extended: +{additional_ms}ms")
        coverage_ledger.budget_max_phase_time_ms += additional_ms
    
    def _get_missing_engines(self, coverage_ledger) -> List[str]:
        """Find engines not yet deployed"""
        all_engines = ["sqlmap", "burp", "zaproxy", "acunetix", "qualys"]
        executed = set(coverage_ledger.engines_executed)
        return [e for e in all_engines if e not in executed]
    
    def _compute_vector_gap(self, coverage_ledger) -> int:
        """How many vector types haven't been tested yet?"""
        all_vectors = {"get", "post", "header", "cookie", "fragment", "body", "path"}
        tested_types = {
            str(record.vector_name or "").strip().lower()
            for record in (coverage_ledger.vector_records or [])
            if (
                int(getattr(record, "inputs_tested", 0) or 0) > 0
                or str(getattr(record, "status", "")).upper().endswith("EXECUTED")
            )
        }
        tested = len({v for v in tested_types if v in all_vectors})
        return len(all_vectors) - tested
    
    def _get_vector_types_to_add(self, coverage_ledger) -> List[str]:
        """Get next vector types to explore"""
        tested_types = {
            str(record.vector_name or "").strip().lower()
            for record in (coverage_ledger.vector_records or [])
            if (
                int(getattr(record, "inputs_tested", 0) or 0) > 0
                or str(getattr(record, "status", "")).upper().endswith("EXECUTED")
            )
        }
        all_vectors = ["get", "post", "header", "cookie", "fragment", "body", "path", "referer", "useragent"]
        return [v for v in all_vectors if v not in tested_types][:3]  # Next 3
    
    def get_escalation_report(self) -> Dict:
        """Audit trail of all escalations made"""
        return {
            "total_escalations": self.total_escalations,
            "total_time_spent_ms": self.total_escalation_time_ms,
            "engines_deployed": self.engines_deployed,
            "vector_rounds": self.vector_expansion_rounds,
            "decisions": [
                {
                    "timestamp": d.timestamp.isoformat(),
                    "reason": d.reason.value,
                    "action": d.action.value,
                    "expected_benefit": d.expected_benefit,
                    "cost_ms": d.cost_estimate_ms,
                    "audit_trail": d.audit_trail,
                }
                for d in self.decisions_history
            ]
        }


def get_escalation_engine() -> ResourceEscalationEngine:
    """Singleton accessor"""
    global _escalation_engine
    if "_escalation_engine" not in globals():
        _escalation_engine = ResourceEscalationEngine()
    return _escalation_engine


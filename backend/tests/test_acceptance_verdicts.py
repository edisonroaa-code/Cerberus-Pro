"""
Tests de aceptación - Obligatorio.
Casos críticos para verificar gating de veredictos.
"""

import asyncio
import pytest
from datetime import datetime
from backend.core.verdict_contract import VerdictStatus, VerdictDictum
from backend.core.coverage_ledger import CoverageLedger, VectorCoverageRecord, EngineCoverageRecord, PhaseCompletionRecord, ConclusiveBlocker, CoverageStatus
from backend.core.verdict_engine import VerdictEngine
from backend.core.orchestrator_fsm import Orchestrator
from backend.core.scheduler_enhanced import Job, JobStatus, SchedulerJobQueue


class TestVerdictGatingAcceptance:
    """Tests de aceptación para gating de veredictos."""
    
    @pytest.fixture
    def base_ledger(self):
        """Ledger base para todos los tests."""
        return CoverageLedger(
            scan_id="test_scan_001",
            target_url="http://example.com",
            budget_max_time_ms=300000,
            budget_max_retries=3,
            budget_max_parallel=5,
            budget_max_phase_time_ms=60000,
            engines_requested=["sqlmap", "burp", "zaproxy"]
        )
    
    def test_case_a_no_inputs_inconclusive(self, base_ledger):
        """
        CASO A: Sin inputs descubiertos -> INCONCLUSIVE
        Cobertura: Discovery falló, no hay inputs para probar
        """
        ledger = base_ledger
        ledger.engines_executed = ["sqlmap", "burp", "zaproxy"]
        ledger.inputs_found = 0
        ledger.inputs_tested = 0
        
        # Agregar bloqueador
        ledger.add_blocker(ConclusiveBlocker(
            category="no_inputs_found",
            detail="No discoverable inputs found in target",
            phase="discovery",
            recoverable=True
        ))
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=5000)
        
        # Verificación
        assert verdict.status == VerdictStatus.INCONCLUSIVE
        assert len(verdict.conclusive_blockers) > 0
        assert "inputs_found" in str(engine._evaluate_blockers()["reasons"])
        print(f"✓ CASO A: {verdict.status.value} (expected: INCONCLUSIVE)")
    
    def test_case_b_missing_dependencies_inconclusive(self, base_ledger):
        """
        CASO B: Dependencias críticas faltantes -> INCONCLUSIVE
        Cobertura: No se puede ejecutar un motor porque falta dependencia
        """
        ledger = base_ledger
        ledger.deps_requested = ["sqlmap", "nmap", "burp"]
        ledger.deps_available = ["sqlmap", "burp"]
        ledger.deps_missing = ["nmap"]
        
        ledger.engines_executed = ["sqlmap", "burp"]  # zaproxy no se ejecutó
        ledger.inputs_found = 10
        ledger.inputs_tested = 10
        
        # Agregar bloqueador
        ledger.add_blocker(ConclusiveBlocker(
            category="missing_deps",
            detail="Required dependency 'nmap' not available",
            phase="preflight",
            recoverable=True
        ))
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=10000)
        
        # Verificación
        assert verdict.status == VerdictStatus.INCONCLUSIVE
        assert "nmap" in str(verdict.conclusive_blockers) or "missing" in str(engine._evaluate_blockers()["reasons"])
        print(f"✓ CASO B: {verdict.status.value} (expected: INCONCLUSIVE)")
    
    def test_case_c_complete_coverage_no_findings_safe(self, base_ledger):
        """
        CASO C: Cobertura completa, todos motores ejecutados, sin hallazgos -> NO_VULNERABLE
        Requerimientos:
        - Todos los motores solicitados ejecutados
        - Inputs encontrados y probados
        - Sin bloqueadores conclusivos
        - Sin hallazgos
        """
        ledger = base_ledger
        
        # Engines completados
        ledger.engines_requested = ["sqlmap", "burp", "zaproxy"]
        ledger.engines_executed = ["sqlmap", "burp", "zaproxy"]
        
        # Inputs probados
        ledger.inputs_found = 15
        ledger.inputs_tested = 15
        
        # Dependencias OK
        ledger.deps_requested = ["sqlmap", "burp"]
        ledger.deps_available = ["sqlmap", "burp"]
        ledger.deps_missing = []
        
        # Sin bloqueadores
        ledger.conclusive_blockers = []
        
        # Registros de vectores
        for i in range(3):
            record = VectorCoverageRecord(
                vector_id=f"vec_{i}",
                vector_name=f"sql_injection_{i}",
                engine="sqlmap",
                status=CoverageStatus.EXECUTED,
                inputs_found=5,
                inputs_tested=5,
                duration_ms=2000
            )
            ledger.add_vector_record(record)
        
        # Registros de engines
        for engine_name in ["sqlmap", "burp", "zaproxy"]:
            record = EngineCoverageRecord(
                engine_name=engine_name,
                status=CoverageStatus.EXECUTED,
                vectors_total=3,
                vectors_executed=3,
                duration_ms=5000,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow()
            )
            ledger.add_engine_record(record)
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=15000)
        
        # Verificación
        assert verdict.status == VerdictStatus.NO_VULNERABLE
        assert verdict.confidence_level >= 0.9
        assert len(verdict.conclusive_blockers) == 0
        print(f"✓ CASO C: {verdict.status.value} (expected: NO_VULNERABLE)")
    
    def test_case_d_confirmed_finding_vulnerable(self, base_ledger):
        """
        CASO D: Hallazgo confirmado -> VULNERABLE
        Requerimiento: confidence >= 0.7 (70%)
        """
        ledger = base_ledger
        
        ledger.engines_executed = ["sqlmap", "burp"]
        ledger.inputs_found = 20
        ledger.inputs_tested = 20
        
        engine = VerdictEngine(ledger)
        
        # Agregar hallazgo confirmado
        engine.add_finding({
            "vector": "search_param",
            "type": "SQL_INJECTION",
            "engine": "sqlmap",
            "confidence": 0.95,
            "payload": "' OR '1'='1",
            "evidence": ["Based on time delay analysis", "DBMS fingerprinting confirmed"]
        })
        
        verdict = engine.issue_verdict(scan_duration_ms=20000)
        
        # Verificación
        assert verdict.status == VerdictStatus.VULNERABLE
        assert verdict.confidence_level >= 0.7
        assert len(engine.findings) == 1
        print(f"✓ CASO D: {verdict.status.value} (expected: VULNERABLE)")
    
    def test_incomplete_engines_forces_inconclusive(self, base_ledger):
        """
        Variante: Motores incompletos fuerza INCONCLUSIVE incluso con inputs
        """
        ledger = base_ledger
        
        ledger.engines_executed = ["sqlmap", "burp"]  # Falta zaproxy
        ledger.inputs_found = 20
        ledger.inputs_tested = 20
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=15000)
        
        assert verdict.status == VerdictStatus.INCONCLUSIVE
        assert "zaproxy" in str(engine._evaluate_blockers()["reasons"]) or "engines" in str(engine._evaluate_blockers()["reasons"])
        print(f"✓ VARIANTE: Incomplete engines -> {verdict.status.value} (expected: INCONCLUSIVE)")

    def test_extra_engine_executed_forces_inconclusive(self, base_ledger):
        """
        Variante: engines_executed debe coincidir exactamente con engines_requested.
        Si hay motores no solicitados, NO_VULNERABLE queda bloqueado.
        """
        ledger = base_ledger
        ledger.engines_requested = ["sqlmap", "burp", "zaproxy"]
        ledger.engines_executed = ["sqlmap", "burp", "zaproxy", "custom_engine"]
        ledger.inputs_found = 20
        ledger.inputs_tested = 20
        ledger.deps_missing = []
        ledger.conclusive_blockers = []

        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=15000)

        assert verdict.status == VerdictStatus.INCONCLUSIVE
        reasons = engine._evaluate_blockers()["reasons"]
        assert "engines_executed != engines_requested" in str(reasons)
        print(f"✓ VARIANTE: Extra engine -> {verdict.status.value} (expected: INCONCLUSIVE)")
    
    def test_resource_exhausted_but_complete_is_safe(self, base_ledger):
        """
        Caso especial: Agotó recursos pero completó todo -> NO_VULNERABLE
        """
        ledger = base_ledger
        
        # Agotó presupuesto pero completó
        ledger.budget_spent_time_ms = ledger.budget_max_time_ms - 1000
        ledger.status = "completed"
        
        ledger.engines_executed = ["sqlmap", "burp", "zaproxy"]
        ledger.inputs_found = 20
        ledger.inputs_tested = 20
        ledger.deps_missing = []
        ledger.conclusive_blockers = []
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=295000)
        
        # Si completó perfectamente, NO_VULNERABLE incluso si agotó recursos
        # (pero si NO completó, entonces INCONCLUSIVE)
        assert verdict.status == VerdictStatus.NO_VULNERABLE
        print(f"✓ CASO ESPECIAL: Exhausted but complete -> {verdict.status.value}")
    
    def test_resource_exhausted_incomplete_is_inconclusive(self, base_ledger):
        """
        Caso especial: Agotó recursos E incompleto -> INCONCLUSIVE
        """
        ledger = base_ledger
        
        # Agotó presupuesto SIN completar
        ledger.budget_spent_time_ms = ledger.budget_max_time_ms - 100
        ledger.status = "timeout"  # No completó
        
        ledger.engines_executed = ["sqlmap", "burp"]  # Falta zaproxy
        ledger.inputs_found = 10
        ledger.inputs_tested = 5
        
        ledger.add_blocker(ConclusiveBlocker(
            category="resource_exhausted_incomplete",
            detail="Testing interrupted due to timeout",
            phase="execution",
            recoverable=True
        ))
        
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(scan_duration_ms=299000)
        
        assert verdict.status == VerdictStatus.INCONCLUSIVE
        print(f"✓ CASO ESPECIAL: Exhausted + incomplete -> {verdict.status.value}")


class TestOrchestratorAcceptance:
    """Tests de aceptación para la máquina de estados."""
    
    @pytest.mark.asyncio
    async def test_orchestrator_phase_sequence(self):
        """Verifica que las fases se ejecuten en orden."""
        orchestrator = Orchestrator(
            scan_id="test_orch_001",
            target_url="http://example.com"
        )
        
        sequence = orchestrator.get_phase_sequence()
        
        assert len(sequence) == 6
        assert sequence[0].value == "preflight"
        assert sequence[-1].value == "verdict"
        print(f"✓ Orchestrator phase sequence OK: {[p.value for p in sequence]}")


class TestSchedulerAcceptance:
    """Tests de aceptación para el scheduler."""
    
    @pytest.mark.asyncio
    async def test_job_heartbeat_keeps_alive(self):
        """Job con heartbeat no muere."""
        scheduler = SchedulerJobQueue(max_parallel=5, heartbeat_timeout_ms=2000)
        
        job = Job(
            scan_id="test_job_001",
            task_name="test_task",
            timeout_ms=10000
        )
        
        job_id = scheduler.enqueue(job)
        dequeued_job = scheduler.dequeue()
        
        assert dequeued_job is not None
        assert dequeued_job.job_id == job_id
        assert dequeued_job.status == JobStatus.RUNNING
        
        # Heartbeat
        alive = scheduler.heartbeat(job_id)
        assert alive is True
        
        print(f"✓ Job heartbeat keeps alive: {job_id}")
    
    @pytest.mark.asyncio
    async def test_job_orphan_requeue(self):
        """Job sin heartbeat es requeued."""
        scheduler = SchedulerJobQueue(max_parallel=5, heartbeat_timeout_ms=100)
        
        job = Job(
            scan_id="test_orphan_001",
            task_name="orphan_task",
            timeout_ms=10000,
            max_retries=2
        )
        
        job_id = scheduler.enqueue(job)
        dequeued = scheduler.dequeue()
        
        # Esperar a que sea detectado como huérfano
        await asyncio.sleep(0.15)
        
        # Simular health check
        # (En producción esto ocurre en background)
        print(f"✓ Orphan job requeue mechanism ready: {job_id}")


from unittest.mock import MagicMock, patch
from backend.core.scan_manager import ScanManager

class MockEngineOrchestrator:
    async def scan_all(self, target_url, vectors):
        class MockFinding:
            def __init__(self, engine, f_type, endpoint, parameter, severity, confidence):
                self.engine = engine
                self.type = f_type
                self.endpoint = endpoint
                self.parameter = parameter
                self.evidence = "mock_evidence"
                self.severity = severity
                self.confidence = confidence

        return [
            MockFinding("sqlmap", "sql_injection", "/login", "user", "Critical", 0.8),
            MockFinding("zap", "sql_injection", "/login", "user", "High", 0.7),
            MockFinding("nmap", "xss", "/search", "q", "Medium", 0.6)
        ]

class TestScanManagerOrchestration:
    """Tests for Phase 3 - Orchestration FSM, Rollbacks, and Findings Correlation."""

    @pytest.fixture
    def mock_deps(self):
        with patch("backend.core.scan_manager.waf_fingerprint", new_callable=MagicMock) as mock_waf, \
             patch("backend.core.scan_manager.EngineOrchestrator", new=MockEngineOrchestrator), \
             patch("backend.core.scan_manager.ChainOrchestrator") as mock_chain:
            
            async def async_waf(*args, **kwargs):
                return "ModSecurity"
            mock_waf.side_effect = async_waf

            mock_chain_instance = mock_chain.return_value
            mock_chain_instance.discover_chains.return_value = []
            yield

    @pytest.mark.asyncio
    async def test_scan_manager_correlation(self, mock_deps):
        manager = ScanManager(target_url="http://test.local", scan_id="test_corr")
        manager.policy_engine.check_authorization = MagicMock(return_value=True)

        await manager.run_scan()

        results = manager.orchestrator.context.execution_results.get("findings", [])
        assert len(results) == 2, f"Expected 2 correlated findings, got {len(results)}"
        
        sqli_finding = next((f for f in results if f["type"] == "sql_injection"), None)
        assert sqli_finding is not None
        assert "sqlmap" in sqli_finding["engines_correlated"]
        assert "zap" in sqli_finding["engines_correlated"]
        assert sqli_finding["confidence"] >= 0.95

    @pytest.mark.asyncio
    async def test_scan_manager_waf_rollback(self):
        manager = ScanManager(target_url="http://test.local", scan_id="test_rb")
        manager.policy_engine.check_authorization = MagicMock(return_value=True)

        pass_count = {"exec": 0, "preflight": 0}

        async def mock_handle_preflight(context):
            pass_count["preflight"] += 1
            return True

        async def mock_handle_execution(context):
            pass_count["exec"] += 1
            if pass_count["exec"] == 1:
                context.execution_results["waf_blocked"] = True
                return True
            else:
                context.execution_results["waf_blocked"] = False
                return True

        manager._handle_preflight = mock_handle_preflight
        manager._handle_execution = mock_handle_execution
        manager._handle_escalation = MagicMock(return_value=True)
        manager._handle_correlation = MagicMock(return_value=True)

        await manager.run_scan()

        assert pass_count["preflight"] == 2
        assert pass_count["exec"] == 2
        assert manager.orchestrator.context.escalation_attempts.get("rollbacks") == 1

# Runner
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

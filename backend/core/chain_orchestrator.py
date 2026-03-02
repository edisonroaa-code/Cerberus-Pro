"""
Cerberus Pro v4 - Chain Discovery & Orchestration Engine

Automatically discovers and executes chains of vulnerabilities:
- SQL Injection → Enumeration → RCE → Shell
- Path Traversal → Credential Discovery → Authentication Bypass
- XXE → Data Exfiltration → Privilege Escalation

Chains are detected through finding relationships and automated based on
attacker capabilities, without human guidance—fully transparent decision tree.
"""

import asyncio
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from pydantic import BaseModel, Field, ConfigDict

from backend.core.engine_adapters import get_engine_adapter_registry
from backend.offensiva.sandbox_runner import get_sandbox_runner

logger = logging.getLogger("cerberus.chain_orchestrator")


class VulnerabilityType(str, Enum):
    """Detected vulnerability types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTHENTICATION_BYPASS = "auth_bypass"
    INSECURE_DESERIALIZE = "insecure_deserialize"
    SECURITY_MISCONFIGURATION = "security_misc"
    WEAK_CRYPTO = "weak_crypto"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    LATERAL_MOVEMENT = "lateral_movement"



class ChainLink(BaseModel):
    """Single step in exploitation chain"""
    source_vuln: VulnerabilityType
    target_vuln: Optional[VulnerabilityType] = None
    technique: str = Field(description="How to exploit: 'enum', 'escalate', 'exfil', 'pivot'")
    confidence: float = Field(ge=0.0, le=1.0, description="0.0-1.0 confidence of chain working")
    preconditions: List[str] = Field(default_factory=list, description="What must be true for this link")
    postconditions: List[str] = Field(default_factory=list, description="What becomes true after")
    time_estimate_ms: int = Field(default=5000, description="Estimated execution time")
    command_template: Optional[str] = None  # e.g., "sqlmap --union --dbs"
    
    model_config = ConfigDict(use_enum_values=True)


class VulnerabilityFinding(BaseModel):
    """A confirmed vulnerability discovery"""
    type: VulnerabilityType
    endpoint: str
    parameter: str
    confirmed: bool = True
    confidence: float = Field(ge=0.5, le=1.0, description="How certain we are")
    payload: Optional[str] = None  # The successful payload
    response_evidence: Optional[str] = None  # Evidence from response
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = Field(default="high")  # low, medium, high, critical
    
    def get_context(self) -> Dict:
        """Context for next step in chain"""
        return {
            "type": self.type,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload": self.payload,
            "confidence": self.confidence,
        }


class ExploitationChain(BaseModel):
    """Complete chain from initial finding to objective"""
    chain_id: str
    initial_finding: VulnerabilityFinding
    chain_links: List[ChainLink] = Field(default_factory=list)
    objective: str = Field(description="What we're trying to achieve: 'data_exfil', 'rce', 'auth_bypass'")
    total_confidence: float = 0.0
    estimated_time_ms: int = 0
    executed: bool = False
    execution_result: Optional[str] = None
    execution_timestamp: Optional[datetime] = None


class ChainOrchestrator:
    """
    Discovers vulnerability chains and executes them automatically.
    
    Decision tree is completely transparent:
    - All chains are logged before execution
    - Preconditions checked before each link
    - Results recorded for audit trail
    """
    
    # Known chain templates: what vulns can lead to what
    CHAIN_TEMPLATES = {
        VulnerabilityType.SQL_INJECTION: [
            ChainLink(
                source_vuln=VulnerabilityType.SQL_INJECTION,
                target_vuln=VulnerabilityType.RCE,
                technique="escalate",
                confidence=0.85,
                preconditions=["database_is_mysql", "user_is_admin"],
                postconditions=["can_execute_os_commands"],
                time_estimate_ms=15000,
                command_template="sqlmap --os-shell"
            ),
            ChainLink(
                source_vuln=VulnerabilityType.SQL_INJECTION,
                target_vuln=None,
                technique="enum",
                confidence=0.95,
                preconditions=["sql_injection_confirmed"],
                postconditions=["database_schema_known", "credentials_available"],
                time_estimate_ms=20000,
                command_template="sqlmap --schema --passwords"
            ),
        ],
        VulnerabilityType.PATH_TRAVERSAL: [
            ChainLink(
                source_vuln=VulnerabilityType.PATH_TRAVERSAL,
                target_vuln=None,
                technique="enum",
                confidence=0.90,
                preconditions=["can_read_files"],
                postconditions=["config_files_readable", "passwords_discoverable"],
                time_estimate_ms=10000,
                command_template="read /etc/passwd, web.config, db configs"
            ),
            ChainLink(
                source_vuln=VulnerabilityType.PATH_TRAVERSAL,
                target_vuln=VulnerabilityType.AUTHENTICATION_BYPASS,
                technique="credential_discovery",
                confidence=0.75,
                preconditions=["config_readable", "credentials_in_config"],
                postconditions=["admin_credentials_obtained"],
                time_estimate_ms=5000,
                command_template="extract credentials from readable configs"
            ),
        ],
        VulnerabilityType.XXE: [
            ChainLink(
                source_vuln=VulnerabilityType.XXE,
                target_vuln=None,
                technique="exfil",
                confidence=0.88,
                preconditions=["xxe_injection_works"],
                postconditions=["sensitive_files_exfiltrated"],
                time_estimate_ms=12000,
                command_template="out-of-band XXE to exfil /etc/passwd"
            ),
        ],
        VulnerabilityType.COMMAND_INJECTION: [
            ChainLink(
                source_vuln=VulnerabilityType.COMMAND_INJECTION,
                target_vuln=VulnerabilityType.RCE,
                technique="escalate",
                confidence=0.92,
                preconditions=["command_injection_confirmed"],
                postconditions=["can_execute_arbitrary_commands"],
                time_estimate_ms=5000,
                command_template="id; whoami; hostname"
            ),
        ],
        VulnerabilityType.RCE: [
            ChainLink(
                source_vuln=VulnerabilityType.RCE,
                target_vuln=VulnerabilityType.LATERAL_MOVEMENT,
                technique="pivot",
                confidence=0.80,
                preconditions=["can_execute_arbitrary_commands"],
                postconditions=["internal_network_mapped"],
                time_estimate_ms=60000,
                command_template="nmap -sT 192.168.1.0/24"
            ),
        ],
    }
    
    def __init__(self):
        self.discovered_findings: List[VulnerabilityFinding] = []
        self.discovered_chains: List[ExploitationChain] = []
        self.executed_chains: Dict[str, ExploitationChain] = {}
        self.chain_execution_history: List[Dict] = []
        self.preflight_summary: Dict[str, Any] = {}
        self.adapter_registry = get_engine_adapter_registry()
        self.sandbox_runner = get_sandbox_runner()

    def _collect_chain_dependencies(self, chain: ExploitationChain) -> List[str]:
        deps: List[str] = []
        for link in chain.chain_links:
            template = str(link.command_template or "").lower()
            if "sqlmap" in template and "sqlmap" not in deps:
                deps.append("sqlmap")
            if "playwright" in template and "playwright" not in deps:
                deps.append("playwright")
            adapter = self.adapter_registry.find_adapter(
                technique=str(link.technique or ""),
                command_template=str(link.command_template or ""),
                vuln_type=str(link.source_vuln.value if hasattr(link.source_vuln, "value") else link.source_vuln),
            )
            if adapter:
                for dep in adapter.required_dependencies():
                    dep_name = str(dep or "").strip()
                    if dep_name and dep_name not in deps:
                        deps.append(dep_name)
        return deps

    async def run_preflight(
        self,
        chain: Optional[ExploitationChain] = None,
        coverage_ledger=None,
        required_dependencies: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        deps: List[str] = []
        for dep in (required_dependencies or []):
            name = str(dep or "").strip()
            if name and (name not in deps):
                deps.append(name)
        if chain is not None:
            for dep in self._collect_chain_dependencies(chain):
                if dep not in deps:
                    deps.append(dep)

        if not deps:
            self.preflight_summary = {"ok": True, "requested": [], "available": [], "missing": []}
            return self.preflight_summary

        from core.resource_escalation import get_escalation_engine

        summary = await get_escalation_engine().run_preflight_checks(
            coverage_ledger=coverage_ledger,
            required_dependencies=deps,
            phase_name="preflight",
        )
        self.preflight_summary = summary
        return summary
    
    def register_finding(self, finding: VulnerabilityFinding) -> None:
        """Register a vulnerability finding"""
        self.discovered_findings.append(finding)
        logger.info(
            f"🔍 Finding registered: {finding.type.value} @ {finding.endpoint}"
            f"/{finding.parameter} (conf: {finding.confidence:.0%})"
        )
    
    def discover_chains(self) -> List[ExploitationChain]:
        """
        Discover all possible exploitation chains from current findings.
        Returns chains sorted by (confidence * value) descending.
        """
        chains = []
        chain_id_counter = 1
        
        for finding in self.discovered_findings:
            if not finding.confirmed:
                continue
            
            # Look up chain templates for this vulnerability type
            templates = self.CHAIN_TEMPLATES.get(finding.type, [])
            
            for template in templates:
                chain = ExploitationChain(
                    chain_id=f"chain_{finding.type.value}_{chain_id_counter}",
                    initial_finding=finding,
                    chain_links=[template],
                    objective=self._infer_objective(finding.type, [template]),
                    total_confidence=template.confidence,
                    estimated_time_ms=template.time_estimate_ms,
                )
                
                # Try to extend chain: can this lead to further exploitation?
                extended_chain = self._try_extend_chain(chain, finding)
                if extended_chain:
                    chain = extended_chain
                
                chains.append(chain)
                chain_id_counter += 1
        
        # Sort by confidence (descending): execute high-confidence chains first
        chains.sort(key=lambda c: c.total_confidence, reverse=True)
        self.discovered_chains = chains
        
        logger.info(f"🔗 Discovered {len(chains)} exploitation chains from {len(self.discovered_findings)} findings")
        for chain in chains:
            logger.debug(
                f"   {chain.chain_id}: {chain.objective} "
                f"({chain.total_confidence:.0%} confidence, ~{chain.estimated_time_ms}ms)"
            )
        
        return chains
    
    def _try_extend_chain(self, chain: ExploitationChain, finding: VulnerabilityFinding) -> Optional[ExploitationChain]:
        """
        Try to extend chain with additional links.
        E.g., SQLi -> Enum -> RCE -> Rev Shell
        """
        last_link = chain.chain_links[-1]
        
        # If last link has a target vuln, try to add more links for that target
        if last_link.target_vuln:
            next_templates = self.CHAIN_TEMPLATES.get(last_link.target_vuln, [])
            if next_templates:
                next_link = next_templates[0]  # Pick first (could be smarter)
                
                # Check if extension is worth it
                combined_confidence = chain.total_confidence * next_link.confidence
                if combined_confidence > 0.65:  # Worth extending if combined conf > 65%
                    chain.chain_links.append(next_link)
                    chain.total_confidence = combined_confidence
                    chain.estimated_time_ms += next_link.time_estimate_ms
                    chain.objective = self._infer_objective(finding.type, chain.chain_links)
        
        return chain if len(chain.chain_links) > 1 else None
    
    def _infer_objective(self, vuln_type: VulnerabilityType, links: List[ChainLink]) -> str:
        """Infer what the chain is trying to achieve"""
        if any(l.technique == "exfil" for l in links):
            return "data_exfiltration"
        elif any(l.target_vuln == VulnerabilityType.RCE for l in links):
            return "remote_code_execution"
        elif any(l.technique == "credential_discovery" for l in links):
            return "credential_discovery_and_auth_bypass"
        else:
            return "information_disclosure"
    
    async def execute_chain(
        self,
        chain: ExploitationChain,
        scheduler=None,
        coverage_ledger=None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute exploitation chain step by step.
        Returns (success, result_details).
        Completely transparent: every step is logged.
        """
        logger.info(
            f"⚡ Executing chain {chain.chain_id}: "
            f"{chain.objective} ({chain.total_confidence:.0%} confidence)"
        )

        preflight = await self.run_preflight(chain=chain, coverage_ledger=coverage_ledger)
        if not preflight.get("ok", True):
            missing = preflight.get("missing", [])
            detail = {
                "chain_id": chain.chain_id,
                "objective": chain.objective,
                "success": False,
                "execution_time_ms": 0,
                "steps_executed": 0,
                "steps_successful": 0,
                "results": [],
                "reason": "preflight_failed",
                "missing_dependencies": missing,
            }
            chain.executed = True
            chain.execution_result = "preflight_failed"
            chain.execution_timestamp = datetime.now(timezone.utc)
            self.executed_chains[chain.chain_id] = chain
            self.chain_execution_history.append(detail)
            logger.warning(f"✗ Chain {chain.chain_id} skipped by preflight. Missing deps: {missing}")
            return False, str(detail)
        
        execution_start = datetime.now(timezone.utc)
        results = []
        
        for i, link in enumerate(chain.chain_links):
            logger.info(f"  [{i+1}/{len(chain.chain_links)}] Executing: {link.technique} "
                       f"({link.source_vuln.value} → {link.target_vuln.value if link.target_vuln else 'objectives'})")
            
            # Check preconditions
            preconditions_met = all(
                self._check_precondition(pc, chain.initial_finding)
                for pc in link.preconditions
            )
            
            if not preconditions_met:
                logger.warning(f"    ⚠ Preconditions not met, skipping this link")
                results.append({
                    "index": i,
                    "link": link.technique,
                    "success": False,
                    "reason": "preconditions_not_met",
                })
                continue
            
            # Execute the link
            result = await self._execute_link(link, chain.initial_finding)
            results.append({
                "index": i,
                "link": link.technique,
                "success": result["success"],
                "output": result.get("output", ""),
                "evidence": result.get("evidence", ""),
            })
            
            if result["success"]:
                logger.info(f"    ✓ Link succeeded: {link.technique}")
            else:
                logger.warning(f"    ✗ Link failed, stopping chain")
                break
        
        # Summarize chain execution
        success = all(r["success"] for r in results)
        execution_time_ms = int((datetime.now(timezone.utc) - execution_start).total_seconds() * 1000)
        
        chain.executed = True
        chain.execution_result = "success" if success else "partial"
        chain.execution_timestamp = execution_start
        
        result_detail = {
            "chain_id": chain.chain_id,
            "objective": chain.objective,
            "success": success,
            "execution_time_ms": execution_time_ms,
            "steps_executed": len(results),
            "steps_successful": sum(1 for r in results if r["success"]),
            "results": results,
        }
        
        self.executed_chains[chain.chain_id] = chain
        self.chain_execution_history.append(result_detail)
        
        logger.info(
            f"✓ Chain {chain.chain_id} completed: {result_detail['steps_successful']}/"
            f"{result_detail['steps_executed']} steps successful, "
            f"{execution_time_ms}ms"
        )
        
        return success, str(result_detail)
    
    async def _execute_link(
        self,
        link: ChainLink,
        finding: VulnerabilityFinding
    ) -> Dict:
        """Execute single chain link. Returns {success, output, evidence}"""
        adapter = self.adapter_registry.find_adapter(
            technique=str(link.technique or ""),
            command_template=str(link.command_template or ""),
            vuln_type=str(link.source_vuln.value if hasattr(link.source_vuln, "value") else link.source_vuln),
        )

        if adapter:
            engine_cmd = adapter.build_command(
                technique=str(link.technique or ""),
                command_template=str(link.command_template or ""),
                endpoint=str(finding.endpoint or ""),
                parameter=str(finding.parameter or ""),
            )
            if engine_cmd:
                run_result = await self.sandbox_runner.run(
                    command=engine_cmd.command,
                    timeout_sec=engine_cmd.timeout_sec,
                    allow_network=engine_cmd.allow_network,
                )
                output = run_result.stdout.strip() or run_result.stderr.strip() or ""
                evidence = (
                    f"engine={engine_cmd.engine} sandbox={run_result.mode} "
                    f"exit_code={run_result.exit_code} duration_ms={run_result.duration_ms}"
                )
                if run_result.error:
                    evidence = f"{evidence} error={run_result.error}"
                return {
                    "success": bool(run_result.success),
                    "output": output[:1000],
                    "evidence": evidence,
                    "link_technique": link.technique,
                }

        return await self._fallback_link_result(link=link, finding=finding)

    async def _fallback_link_result(
        self,
        link: ChainLink,
        finding: VulnerabilityFinding
    ) -> Dict:
        """Fallback path when no concrete adapter can run.

        Runtime policy: never fabricate successful offensive outcomes.
        """
        logger.warning(
            "Chain link skipped (no adapter): technique=%s endpoint=%s parameter=%s",
            link.technique,
            finding.endpoint,
            finding.parameter,
        )
        return {
            "success": False,
            "output": "",
            "evidence": "No concrete adapter available; fallback chain execution is disabled.",
            "link_technique": link.technique,
        }
    
    def _check_precondition(self, precondition: str, finding: VulnerabilityFinding) -> bool:
        """
        Check if precondition is met.
        In production, checks environment variables, previous findings, etc.
        """
        # Simplified: assume preconditions are met if we have high-confidence finding
        return finding.confidence > 0.6
    
    def get_chain_report(self) -> Dict:
        """Audit trail of all chains discovered and executed"""
        return {
            "total_findings": len(self.discovered_findings),
            "total_chains_discovered": len(self.discovered_chains),
            "total_chains_executed": len(self.executed_chains),
            "execution_results": self.chain_execution_history,
            "findings": [
                {
                    "type": f.type.value,
                    "endpoint": f.endpoint,
                    "parameter": f.parameter,
                    "confidence": f.confidence,
                    "discovered_at": f.discovered_at.isoformat(),
                }
                for f in self.discovered_findings
            ],
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "objective": c.objective,
                    "confidence": c.total_confidence,
                    "steps": len(c.chain_links),
                    "executed": c.executed,
                    "result": c.execution_result,
                }
                for c in self.discovered_chains
            ],
        }


def get_chain_orchestrator() -> ChainOrchestrator:
    """Singleton accessor"""
    global _chain_orchestrator
    if "_chain_orchestrator" not in globals():
        _chain_orchestrator = ChainOrchestrator()
    return _chain_orchestrator

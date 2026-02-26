"""
Cerberus Cortex AI — Backend Gemini Integration.

Provides real-time tactical intelligence for the scan orchestrator.
Falls back to heuristic logic if Gemini is unavailable or slow (>3s).
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("cerberus.core.cortex_ai")

# ---------------------------------------------------------------------------
# SDK initialisation (lazy)
# ---------------------------------------------------------------------------
_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        logger.warning("GEMINI_API_KEY not set — Cortex AI disabled, using heuristics")
        return None
    try:
        from google import genai
        _client = genai.Client(api_key=api_key)
        logger.info("Cortex AI initialised (Gemini backend)")
        return _client
    except Exception as e:
        logger.error(f"Failed to initialise Gemini client: {e}")
        return None


CORTEX_MODEL = "gemini-2.0-flash"
CORTEX_TIMEOUT = 3.0  # seconds


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TacticalDecision:
    action: str          # "change_profile", "increase_jitter", "switch_tamper", "skip", "retry"
    params: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    source: str = "heuristic"  # "gemini" or "heuristic"
    confidence: float = 0.5


@dataclass
class EscalationPlan:
    chains_to_execute: List[str] = field(default_factory=list)
    chains_to_skip: List[str] = field(default_factory=list)
    priority_order: List[str] = field(default_factory=list)
    reasoning: str = ""
    source: str = "heuristic"


@dataclass
class CorrelatedFindings:
    groups: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    reasoning: str = ""
    source: str = "heuristic"


# ---------------------------------------------------------------------------
# Core AI functions
# ---------------------------------------------------------------------------

async def analyze_waf_signal(
    signal_data: Dict[str, Any],
    scan_context: Dict[str, Any],
) -> TacticalDecision:
    """
    Analyse a WAF block/rate-limit signal and return a tactical decision.

    Called by scan_manager when block_rate exceeds threshold.
    """
    client = _get_client()
    if client is None:
        return _heuristic_waf_decision(signal_data, scan_context)

    prompt = f"""Eres el módulo de IA táctica del sistema de pentesting Cerberus.
Estás recibiendo señales de bloqueo de un WAF durante un scan activo.

CONTEXTO DEL SCAN:
- Target: {scan_context.get('target_url', 'unknown')}
- Perfil actual: {scan_context.get('current_profile', 'standard')}
- Block rate: {signal_data.get('block_rate', 0):.0%}
- Latencia promedio: {signal_data.get('avg_latency_ms', 0)}ms
- Captcha detectado: {signal_data.get('captcha_detected', False)}
- Rate limit: {signal_data.get('rate_limited', False)}
- Fase actual: {scan_context.get('current_phase', 'execution')}
- Engines activos: {scan_context.get('engines', [])}

RESPONDE SOLO EN JSON VÁLIDO con esta estructura exacta:
{{
    "action": "change_profile|increase_jitter|switch_tamper|enable_stealth|pause|retry",
    "params": {{"profile": "...", "jitter_multiplier": 1.5, "tamper": "..."}},
    "reasoning": "explicación breve en español",
    "confidence": 0.0-1.0
}}"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL,
                    contents=prompt,
                ),
            ),
            timeout=CORTEX_TIMEOUT,
        )
        text = response.text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        data = json.loads(text)
        return TacticalDecision(
            action=data.get("action", "retry"),
            params=data.get("params", {}),
            reasoning=data.get("reasoning", ""),
            source="gemini",
            confidence=float(data.get("confidence", 0.7)),
        )
    except asyncio.TimeoutError:
        logger.warning("Cortex AI timeout (>3s) — falling back to heuristic")
        return _heuristic_waf_decision(signal_data, scan_context)
    except Exception as e:
        logger.warning(f"Cortex AI error: {e} — falling back to heuristic")
        return _heuristic_waf_decision(signal_data, scan_context)


async def suggest_escalation(
    findings: List[Dict[str, Any]],
    coverage_summary: Dict[str, Any],
) -> EscalationPlan:
    """
    Given current findings and coverage, suggest which escalation chains to prioritise.
    """
    client = _get_client()
    if client is None or not findings:
        return _heuristic_escalation(findings, coverage_summary)

    findings_summary = json.dumps(findings[:10], default=str, indent=2)

    prompt = f"""Eres el módulo de IA táctica de Cerberus.
Analiza los hallazgos de un scan de vulnerabilidades y recomienda la estrategia de escalación.

HALLAZGOS ACTUALES:
{findings_summary}

COBERTURA:
- Coverage: {coverage_summary.get('coverage_percentage', 0):.0f}%
- Engines ejecutados: {coverage_summary.get('engines_executed', [])}
- Bloqueadores: {coverage_summary.get('blockers', [])}

RESPONDE SOLO EN JSON VÁLIDO:
{{
    "chains_to_execute": ["data_exfil", "rce", "auth_bypass"],
    "chains_to_skip": ["lateral_movement"],
    "priority_order": ["rce", "data_exfil"],
    "reasoning": "explicación breve en español"
}}"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=CORTEX_TIMEOUT,
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        data = json.loads(text)
        return EscalationPlan(
            chains_to_execute=data.get("chains_to_execute", []),
            chains_to_skip=data.get("chains_to_skip", []),
            priority_order=data.get("priority_order", []),
            reasoning=data.get("reasoning", ""),
            source="gemini",
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cortex escalation fallback: {e}")
        return _heuristic_escalation(findings, coverage_summary)


async def correlate_findings_ai(
    findings: List[Dict[str, Any]],
) -> CorrelatedFindings:
    """
    Use AI to find non-obvious relationships between findings.
    """
    client = _get_client()
    if client is None or len(findings) < 2:
        return _heuristic_correlation(findings)

    findings_text = json.dumps(findings[:15], default=str, indent=2)

    prompt = f"""Eres el módulo de correlación inteligente de Cerberus.
Analiza estos hallazgos de pentesting y encuentra relaciones no-obvias.

HALLAZGOS:
{findings_text}

RESPONDE SOLO EN JSON VÁLIDO:
{{
    "groups": [
        {{"id": "group1", "finding_indices": [0, 2], "relationship": "SQLi + RCE chain"}},
    ],
    "relationships": [
        "El SQLi en /admin permite enumerar credenciales que habilitan el RCE en /exec"
    ],
    "reasoning": "explicación"
}}"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=CORTEX_TIMEOUT,
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        data = json.loads(text)
        return CorrelatedFindings(
            groups=data.get("groups", []),
            relationships=data.get("relationships", []),
            reasoning=data.get("reasoning", ""),
            source="gemini",
        )
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Cortex correlation fallback: {e}")
        return _heuristic_correlation(findings)


async def generate_forensic_narrative(
    verdict_status: str,
    findings: List[Dict[str, Any]],
    coverage_pct: float,
) -> str:
    """
    Generate a professional forensic narrative for the report.
    """
    client = _get_client()
    if client is None:
        return _heuristic_narrative(verdict_status, findings, coverage_pct)

    prompt = f"""Genera un resumen ejecutivo forense EN ESPAÑOL para un reporte de pentesting.

VEREDICTO: {verdict_status}
HALLAZGOS: {len(findings)}
COBERTURA: {coverage_pct:.0f}%
DETALLES: {json.dumps(findings[:5], default=str)}

El resumen debe ser:
- Profesional y técnico
- 3-5 párrafos
- Incluir recomendaciones de remediación
- Tono de ciberseguridad forense"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=5.0,  # Longer timeout for narrative
        )
        return response.text
    except Exception as e:
        logger.warning(f"Cortex narrative fallback: {e}")
        return _heuristic_narrative(verdict_status, findings, coverage_pct)


# ---------------------------------------------------------------------------
# Structured Finding Parser
# ---------------------------------------------------------------------------

def parse_structured_findings(findings: list[dict]) -> list[dict]:
    """
    Parse raw findings into structured fields:
    - db_name, db_user, tables, os_info extracted from evidence
    - severity_score normalized to CVSS-like 0-10 scale
    - remediation suggestion per finding type
    """
    import re

    SEVERITY_MAP = {
        "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0
    }
    REMEDIATION = {
        "sql_injection": "Usar consultas parametrizadas (prepared statements). Validar y sanitizar inputs.",
        "rce": "Deshabilitar funciones peligrosas (exec, system). Aplicar sandboxing.",
        "xss": "Escapar output HTML. Implementar Content-Security-Policy.",
        "command_injection": "Evitar shell commands. Usar APIs seguras del lenguaje.",
        "lfi": "No usar input del usuario en rutas de archivos. Whitelist de paths permitidos.",
        "auth_bypass": "Implementar autenticación robusta. Revisar lógica de sesiones.",
    }

    structured = []
    for f in findings:
        sf = f.copy()
        evidence_text = " ".join(f.get("evidence", [])) if isinstance(f.get("evidence"), list) else str(f.get("evidence", ""))
        
        # Extract DB info from evidence
        db_match = re.search(r"database[:\s]+['\"]?(\w+)", evidence_text, re.I)
        user_match = re.search(r"(?:current\s+)?user[:\s]+['\"]?(\S+)", evidence_text, re.I)
        table_matches = re.findall(r"(?:table|tabla)[:\s]+['\"]?(\w+)", evidence_text, re.I)
        os_match = re.search(r"(?:os|sistema)[:\s]+['\"]?([^\n'\"]+)", evidence_text, re.I)
        version_match = re.search(r"version[:\s]+['\"]?([^\n'\"]+)", evidence_text, re.I)

        sf["structured"] = {
            "db_name": db_match.group(1) if db_match else None,
            "db_user": user_match.group(1) if user_match else None,
            "tables_found": table_matches or [],
            "os_info": os_match.group(1).strip() if os_match else None,
            "db_version": version_match.group(1).strip() if version_match else None,
        }

        # Normalize severity
        raw_sev = str(f.get("severity", "medium")).lower()
        sf["severity_score"] = SEVERITY_MAP.get(raw_sev, 5.5)
        
        # Add remediation
        ftype = str(f.get("type", "")).lower()
        sf["remediation"] = REMEDIATION.get(ftype, "Revisar manualmente y aplicar controles de seguridad.")

        structured.append(sf)

    return structured


# ---------------------------------------------------------------------------
# Heuristic fallbacks
# ---------------------------------------------------------------------------

def _heuristic_waf_decision(
    signal: Dict[str, Any], ctx: Dict[str, Any]
) -> TacticalDecision:
    block_rate = signal.get("block_rate", 0)
    captcha = signal.get("captcha_detected", False)
    rate_limited = signal.get("rate_limited", False)

    if captcha:
        return TacticalDecision(
            action="enable_stealth",
            params={"use_browser_stealth": True, "jitter_multiplier": 2.0},
            reasoning="Captcha detectado — activar BrowserStealth para bypass",
            confidence=0.8,
        )
    if rate_limited:
        return TacticalDecision(
            action="increase_jitter",
            params={"jitter_multiplier": 2.5, "threads": 1},
            reasoning="Rate limit activo — reducir velocidad drásticamente",
            confidence=0.9,
        )
    if block_rate > 0.5:
        return TacticalDecision(
            action="change_profile",
            params={"profile": "stealth", "tamper": "between,randomcase,space2comment"},
            reasoning=f"Block rate alto ({block_rate:.0%}) — cambiar a perfil sigiloso",
            confidence=0.7,
        )
    if block_rate > 0.2:
        return TacticalDecision(
            action="switch_tamper",
            params={"tamper": "randomcase,space2comment"},
            reasoning=f"Block rate moderado ({block_rate:.0%}) — rotar tampers",
            confidence=0.6,
        )
    return TacticalDecision(
        action="retry",
        params={},
        reasoning="Señales normales — continuar",
        confidence=0.5,
    )


def _heuristic_escalation(
    findings: List[Dict], coverage: Dict
) -> EscalationPlan:
    chains = []
    for f in findings:
        ftype = f.get("type", "")
        if ftype in ("sql_injection", "rce"):
            chains.append("data_exfil")
        if ftype == "rce":
            chains.append("rce")

    return EscalationPlan(
        chains_to_execute=list(set(chains)) or ["data_exfil"],
        chains_to_skip=[],
        priority_order=chains[:3],
        reasoning="Escalación heurística basada en tipos de findings",
    )


def _heuristic_correlation(findings: List[Dict]) -> CorrelatedFindings:
    groups = []
    by_endpoint = {}
    for i, f in enumerate(findings):
        ep = f.get("endpoint", "unknown")
        by_endpoint.setdefault(ep, []).append(i)

    for ep, indices in by_endpoint.items():
        if len(indices) >= 2:
            groups.append({
                "id": f"ep_{ep}",
                "finding_indices": indices,
                "relationship": f"Multiple findings on {ep}",
            })

    return CorrelatedFindings(
        groups=groups,
        relationships=[],
        reasoning="Correlación por endpoint (heurística)",
    )


def _heuristic_narrative(
    verdict: str, findings: List[Dict], coverage: float
) -> str:
    n = len(findings)
    if verdict == "VULNERABLE":
        return (
            f"## Resumen Ejecutivo\n\n"
            f"Se identificaron **{n} hallazgo(s)** confirmado(s) con una cobertura del {coverage:.0f}%. "
            f"El sistema objetivo presenta vulnerabilidades que requieren remediación inmediata.\n\n"
            f"**Recomendación**: Parchear las vulnerabilidades identificadas y realizar un re-test."
        )
    if verdict == "NO_VULNERABLE":
        return (
            f"## Resumen Ejecutivo\n\n"
            f"No se identificaron vulnerabilidades con una cobertura del {coverage:.0f}%. "
            f"El sistema objetivo no presenta vectores de ataque explotables con las técnicas empleadas.\n\n"
            f"**Recomendación**: Mantener monitoreo y repetir auditoría periódicamente."
        )
    return (
        f"## Resumen Ejecutivo\n\n"
        f"El análisis fue **inconcluso** (cobertura: {coverage:.0f}%). "
        f"No se pudo determinar con certeza el estado de seguridad del objetivo. "
        f"Existen bloqueadores que impidieron completar la evaluación.\n\n"
        f"**Recomendación**: Resolver bloqueadores y re-ejecutar con cobertura completa."
    )

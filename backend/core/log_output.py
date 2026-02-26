"""
Log output helpers extracted from ares_api.py.
"""

from __future__ import annotations

import re


def sanitize_line(line: str) -> str:
    """Sanitize and mask sensitive data in output."""
    output = str(line or "")
    output = re.sub(
        r"(?i)(password|passwd|pwd|token|api.?key|secret)\s*[=:]\s*[^\s\\\n\r]+",
        r"\1=***REDACTED***",
        output,
    )
    output = re.sub(
        r"(?i)(user|username|login)\s*[=:]\s*[^\s\\\n\r@]+",
        r"\1=***REDACTED***",
        output,
    )
    output = re.sub(r"0x[0-9a-fA-F]{16,}", "0x***REDACTED***", output)
    return output


def translate_log(line: str) -> str:
    """Add Spanish explanations in parentheses for technical SQLMap output."""
    output = str(line or "")
    translations = [
        ("boolean-based blind", "Inyección ciega basada en booleanos: comparando respuestas SI/NO"),
        ("error-based", "Inyección basada en errores: forzando a la DB a revelar datos en mensajes de error"),
        ("time-based blind", "Inyección ciega basada en tiempo: midiendo pausas en la respuesta (SLEEP)"),
        ("UNION query", "Inyección basada en UNION: combinando resultados con otra tabla legítima"),
        ("stacked queries", "Consultas apiladas: ejecutando múltiples comandos SQL separados por ';'"),
        ("inline queries", "Consultas en línea: inyectando una subconsulta dentro de la principal"),
        ("appears to be", "PARECE SER VULNERABLE"),
        ("is vulnerable", "¡ES VULNERABLE!"),
        ("testing", "Probando técnica"),
        ("heuristic", "Análisis heurístico"),
        ("reflective value", "Valor reflejado detectado (posible falso positivo o filtrado)"),
        ("parameter '", "parámetro '"),
        ("back-end DBMS", "Motor de Base de Datos (DBMS)"),
        ("skip test payloads", "omitir payloads de prueba de otros motores"),
        ("information_schema", "Esquema de información (metadatos de la DB)"),
    ]
    for eng, esp in translations:
        if eng.lower() in output.lower() and esp not in output:
            output = f"{output} ({esp})"
    return output

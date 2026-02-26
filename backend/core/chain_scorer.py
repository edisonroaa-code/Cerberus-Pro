"""
Chain Scorer (CVSS-aware) - basic implementation for Sprint 2.1

Provides a lightweight scoring function combining CVSS-like base score
with temporal and environmental modifiers. Intended as a starter
implementation to be refined in Sprint 2.1.
"""
from typing import Dict


def compute_chain_score(base_cvss: float, temporal: float = 0.0, environmental: float = 0.0) -> float:
    """Compute a final chain score (0-100) from components.

    Args:
        base_cvss: base CVSS score (0-10)
        temporal: temporal modifier (-1.0 .. 1.0)
        environmental: environmental modifier (-1.0 .. 1.0)

    Returns:
        score in 0..100 (higher = more desirable to execute)
    """
    # Normalize base_cvss (0-10) -> 0-1
    base_norm = max(0.0, min(1.0, base_cvss / 10.0))

    # Clamp modifiers
    temporal = max(-1.0, min(1.0, temporal))
    environmental = max(-1.0, min(1.0, environmental))

    # Weighted combination: base most important
    combined = (0.7 * base_norm) + (0.2 * (temporal + 1) / 2.0) + (0.1 * (environmental + 1) / 2.0)

    # Convert to 0-100
    return round(max(0.0, min(1.0, combined)) * 100, 2)


def score_chain_template(template: Dict) -> float:
    """Score a chain template dict containing metadata fields.

    Expected keys: 'base_cvss', 'temporal', 'environmental'
    """
    base = float(template.get("base_cvss", 5.0))
    temporal = float(template.get("temporal", 0.0))
    env = float(template.get("environmental", 0.0))
    return compute_chain_score(base, temporal, env)

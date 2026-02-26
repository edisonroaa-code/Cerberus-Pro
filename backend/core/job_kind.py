"""
Job kind normalization helpers extracted from ares_api.py.
"""

from __future__ import annotations

from typing import Any, List, Sequence


def normalize_job_kind(kind: Any, *, canonical_job_kind: str, legacy_job_kinds: Sequence[str]) -> str:
    value = str(kind or "").strip().lower()
    if value in {str(canonical_job_kind), *[str(v) for v in legacy_job_kinds]}:
        return str(canonical_job_kind)
    return value or str(canonical_job_kind)


def job_kind_candidates(kind: Any, *, canonical_job_kind: str, legacy_job_kinds: Sequence[str]) -> List[str]:
    normalized = normalize_job_kind(
        kind,
        canonical_job_kind=canonical_job_kind,
        legacy_job_kinds=legacy_job_kinds,
    )
    if normalized == str(canonical_job_kind):
        return [str(canonical_job_kind), *[str(v) for v in legacy_job_kinds]]
    return [normalized]

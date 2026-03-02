"""
History Router — Extracted from ares_api.py (Fase 5 Refactoring).
Handles: get_history, get_history_detail, get_history_profile.
"""

import os
import json
import logging
from typing import List

from backend.core.api_contracts import HistorySummaryItem, HistoryProfileResponse

from fastapi import APIRouter, HTTPException, Depends

from auth_security import (
    Permission, require_permission, JWTPayload,
)

logger = logging.getLogger("cerberus.routers.history")
router = APIRouter()


def _get_history_dir():
    from ares_api import HISTORY_DIR
    return HISTORY_DIR


def _get_safe_history_path(filename):
    from ares_api import _safe_history_path
    return _safe_history_path(filename)


def _get_normalize_job_kind(kind):
    from ares_api import _normalize_job_kind
    return _normalize_job_kind(kind)


# ============================================================================
# HISTORY ENDPOINTS
# ============================================================================

@router.get("", response_model=List[HistorySummaryItem])
async def get_history(current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    """List all saved scan reports"""
    history_dir = _get_history_dir()
    try:
        files = sorted(
            [f for f in os.listdir(history_dir) if f.endswith('.json')],
            reverse=True
        )
        history_list = []
        for f in files:
            path = os.path.join(history_dir, f)
            with open(path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                cov = data.get("coverage") if isinstance(data, dict) else {}
                kind = ""
                try:
                    kind = _get_normalize_job_kind((cov or {}).get("kind"))
                except Exception:
                    kind = ""
                history_list.append({
                    "id": f,
                    "timestamp": data.get("timestamp"),
                    "target": data.get("target"),
                    "vulnerable": data.get("vulnerable"),
                    "verdict": data.get("verdict"),
                    "conclusive": data.get("conclusive"),
                    "count": data.get("count"),
                    "profile": data.get("profile"),
                    "mode": data.get("mode"),
                    "kind": kind
                })
        return history_list
    except Exception as e:
        logger.error(f"Error listing history: {str(e)}")
        return []


@router.get("/{filename}")
async def get_history_detail(filename: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    """Get detailed report from history"""
    path = _get_safe_history_path(filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Historial no encontrado")

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading history file: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al leer el archivo de historial")


@router.get("/{filename}/profile/{profile_name}", response_model=HistoryProfileResponse)
async def get_history_profile(
    filename: str,
    profile_name: str,
    current_user: JWTPayload = Depends(require_permission(Permission.REPORT_READ)),
):
    """Get specific report profile: executive | technical | forensic"""
    path = _get_safe_history_path(filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Historial no encontrado")

    valid_profiles = {"executive", "technical", "forensic"}
    profile_key = profile_name.lower().strip()
    if profile_key not in valid_profiles:
        raise HTTPException(status_code=400, detail="Perfil invalido")

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        profiles = data.get("profiles", {})
        if profile_key not in profiles:
            raise HTTPException(status_code=404, detail="Perfil no disponible en este reporte")
        return {"id": filename, "profile": profile_key, "content": profiles[profile_key]}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reading history profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Error al leer perfil del historial")

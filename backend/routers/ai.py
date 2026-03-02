from fastapi import APIRouter, Depends, HTTPException
from auth_security import get_current_user, JWTPayload
from backend.core.cortex_ai import analyze_waf_signal, generate_forensic_narrative, TacticalDecision
from pydantic import BaseModel
from typing import Dict, Any, List, Optional

router = APIRouter()

class WafAnalysisRequest(BaseModel):
    signal_data: Dict[str, Any]
    scan_context: Dict[str, Any]

class NarrativeRequest(BaseModel):
    verdict_status: str
    findings: List[Dict[str, Any]]
    coverage_pct: float

@router.post("/analyze-waf")
async def analyze_waf_endpoint(
    req: WafAnalysisRequest,
    current_user: JWTPayload = Depends(get_current_user)
):
    """Proxy for AI WAF analysis (Backend-only SDK)"""
    try:
        decision = await analyze_waf_signal(req.signal_data, req.scan_context)
        return decision.__dict__
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-narrative")
async def generate_narrative_endpoint(
    req: NarrativeRequest,
    current_user: JWTPayload = Depends(get_current_user)
):
    """Proxy for AI Narrative generation"""
    try:
        narrative = await generate_forensic_narrative(
            req.verdict_status,
            req.findings,
            req.coverage_pct
        )
        return {"narrative": narrative}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

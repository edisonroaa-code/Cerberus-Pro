import os
import json
import logging
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from auth_security import Permission, require_permission, JWTPayload

logger = logging.getLogger("cerberus.routers.loot")
router = APIRouter()

def _get_loot_dir():
    from backend.ares_runtime import LOOT_DIR
    return LOOT_DIR

def _get_safe_loot_path(filename: str):
    loot_dir = _get_loot_dir()
    safe_filename = "".join([c for c in filename if c.isalpha() or c.isdigit() or c in (' ', '.', '_', '-')]).rstrip()
    if not safe_filename.endswith('.json'):
        safe_filename += '.json'
    return os.path.join(loot_dir, safe_filename)

@router.get("", response_model=List[Dict[str, Any]])
async def get_all_loot(current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    """List all extracted data (Loot)"""
    loot_dir = _get_loot_dir()
    try:
        files = sorted(
            [f for f in os.listdir(loot_dir) if f.endswith('.json') and f.startswith("loot_")],
            reverse=True
        )
        loot_list = []
        for f in files:
            path = os.path.join(loot_dir, f)
            with open(path, 'r', encoding='utf-8') as file:
                try:
                    data = json.load(file)
                    loot_list.append({
                        "id": f,
                        "scan_id": data.get("scan_id"),
                        "target": data.get("target"),
                        "timestamp": data.get("timestamp"),
                        "technique_used": data.get("technique_used"),
                        "extracted_data": data.get("extracted_data")
                    })
                except Exception as e:
                    logger.error(f"Error parsing loot file {f}: {e}")
        return loot_list
    except Exception as e:
        logger.error(f"Error listing loot directory: {e}")
        return []

@router.get("/{filename}")
async def get_loot_detail(filename: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    """Get single loot file detail"""
    path = _get_safe_loot_path(filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Loot no encontrado")
        
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading loot file: {e}")
        raise HTTPException(status_code=500, detail="Error leyendo el botín")

@router.delete("/{filename}")
async def delete_loot(filename: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_MODIFY))):
    """Delete a loot record"""
    path = _get_safe_loot_path(filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Loot no encontrado")
        
    try:
        os.remove(path)
        return {"status": "success", "message": "Loot eliminado"}
    except Exception as e:
        logger.error(f"Error deleting loot file: {e}")
        raise HTTPException(status_code=500, detail="Error borrando el botín")

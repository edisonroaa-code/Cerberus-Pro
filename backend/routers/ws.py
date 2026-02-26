# API-001: DEPRECATED — This router is NOT mounted in ares_api.py.
# The canonical WebSocket endpoint lives in ares_api.py (@app.websocket("/ws")).
# TODO: Either mount or delete during ARCH-002 refactor.
from fastapi import APIRouter

router = APIRouter()


@router.get("/ws/health")
async def ws_health():
    return {"ok": True, "module": "ws"}

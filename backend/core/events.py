"""
Global Event Broadcaster to decouple core algorithms from FastAPI WebSockets.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class CerberusBroadcaster:
    _ws_handler: Optional[Callable] = None

    @classmethod
    def register_ws_handler(cls, handler: Callable) -> None:
        """Registers the FastAPI websocket broadcast function."""
        cls._ws_handler = handler

    @classmethod
    async def broadcast_ws_message(cls, component: str, msg_type: str, msg: str) -> None:
        """Broadcast via Websockets if a handler is registered (FastAPI), otherwise just log it."""
        if cls._ws_handler:
            try:
                # Expecting object dict with type, level, msg
                payload = {
                    "type": msg_type,
                    "level": "INFO",
                    "msg": msg
                }
                await cls._ws_handler(payload)
            except Exception as e:
                logger.debug(f"Event broadcast failed: {e}")
        else:
            # Fallback for CLI scripts and tests
            logger.info(f"[{component}] <{msg_type}> {msg}")


class ScanEventCoordinator:
    """
    Coordinates scan lifecycle milestones to enforce deterministic orchestration.

    Stages are intentionally simple string labels so any runtime can reuse them.
    """

    def __init__(self, scan_id: str) -> None:
        self.scan_id = str(scan_id or "unknown")
        self._events: Dict[str, asyncio.Event] = {}
        self._timeline: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._last_stage: Optional[str] = None

    async def mark(self, stage: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        stage_name = str(stage or "").strip()
        if not stage_name:
            return
        payload = dict(metadata or {})
        payload["stage"] = stage_name
        payload["scan_id"] = self.scan_id
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()

        async with self._lock:
            event = self._events.setdefault(stage_name, asyncio.Event())
            event.set()
            self._last_stage = stage_name
            self._timeline.append(payload)

        try:
            await CerberusBroadcaster.broadcast_ws_message(
                "ORQUESTADOR",
                "scan_event",
                f"[{self.scan_id}] {stage_name}",
            )
        except Exception:
            pass

    async def wait_for(self, stage: str, timeout: Optional[float] = None) -> bool:
        stage_name = str(stage or "").strip()
        if not stage_name:
            return False
        event = self._events.setdefault(stage_name, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def snapshot(self) -> Dict[str, Any]:
        done = {name: event.is_set() for name, event in self._events.items()}
        return {
            "scan_id": self.scan_id,
            "last_stage": self._last_stage,
            "stages": done,
            "timeline": list(self._timeline),
        }


_COORDINATORS: Dict[str, ScanEventCoordinator] = {}
_COORD_LOCK = Lock()


def get_scan_event_coordinator(scan_id: str) -> ScanEventCoordinator:
    key = str(scan_id or "unknown")
    with _COORD_LOCK:
        coord = _COORDINATORS.get(key)
        if coord is None:
            coord = ScanEventCoordinator(scan_id=key)
            _COORDINATORS[key] = coord
        return coord


def release_scan_event_coordinator(scan_id: str) -> None:
    key = str(scan_id or "unknown")
    with _COORD_LOCK:
        _COORDINATORS.pop(key, None)

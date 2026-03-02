"""
Global Event Broadcaster to decouple core algorithms from FastAPI WebSockets.
"""
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

class CerberusBroadcaster:
    _ws_handler: Optional[Callable] = None

    @classmethod
    def register_ws_handler(cls, handler: Callable):
        """Registers the FastAPI websocket broadcast function."""
        cls._ws_handler = handler

    @classmethod
    async def broadcast_ws_message(cls, component: str, msg_type: str, msg: str):
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

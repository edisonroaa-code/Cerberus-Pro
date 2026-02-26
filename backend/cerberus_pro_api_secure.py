#!/usr/bin/env python3
"""
Cerberus Pro Secure API - Compatibility Entry Point

Canonical runtime module is `backend/ares_api.py`.
This file stays as a stable import/uvicorn target for backward compatibility.
"""

import sys
import os
import importlib
from types import ModuleType
from typing import Any

# Add parent directory to path for absolute imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_APP_MODULE_NAME = "ares_api"
_app_module: ModuleType = importlib.import_module(_APP_MODULE_NAME)

# Export FastAPI app for uvicorn
app = getattr(_app_module, "app")


def __getattr__(name: str) -> Any:
    """
    Proxy legacy attribute access to `ares_api`.
    This preserves imports used by tests/tools, e.g.:
      from backend.cerberus_pro_api_secure import validate_omni_config
    """
    try:
        return getattr(_app_module, name)
    except AttributeError as exc:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'") from exc

# Export for uvicorn
__all__ = ["app"]

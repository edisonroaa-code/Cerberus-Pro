"""
Engine adapter registry for chain execution.

Phase 3 objective:
- Decouple chain orchestration from concrete scanner CLIs.
- Allow parallel/isolated orchestration through a stable adapter contract.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence


@dataclass
class EngineCommand:
    engine: str
    command: List[str]
    timeout_sec: int = 120
    allow_network: bool = True
    metadata: Dict[str, str] = field(default_factory=dict)


class EngineAdapter(Protocol):
    name: str

    def supports(self, technique: str, command_template: str, vuln_type: str) -> bool:
        ...

    def required_dependencies(self) -> Sequence[str]:
        ...

    def build_command(
        self,
        technique: str,
        command_template: str,
        endpoint: str,
        parameter: str,
    ) -> Optional[EngineCommand]:
        ...


def _default_sqlmap_path() -> str:
    env_path = str(os.environ.get("CERBERUS_SQLMAP_PATH", "")).strip()
    if env_path:
        return env_path
    repo_default = Path(__file__).resolve().parents[2] / "cerberus_engine" / "sqlmap.py"
    return str(repo_default)


class SqlmapAdapter:
    name = "sqlmap"

    def supports(self, technique: str, command_template: str, vuln_type: str) -> bool:
        tmpl = (command_template or "").lower()
        return ("sqlmap" in tmpl) or (vuln_type == "sql_injection")

    def required_dependencies(self) -> Sequence[str]:
        return ["sqlmap"]

    def build_command(
        self,
        technique: str,
        command_template: str,
        endpoint: str,
        parameter: str,
    ) -> Optional[EngineCommand]:
        if not endpoint:
            return None

        sqlmap_path = _default_sqlmap_path()
        if not Path(sqlmap_path).exists() and not shutil.which("sqlmap"):
            return None

        if Path(sqlmap_path).exists():
            cmd: List[str] = [sys.executable, sqlmap_path]
        else:
            cmd = ["sqlmap"]

        # Keep chain executions deterministic and non-interactive.
        cmd.extend(["--batch", "--disable-coloring", "--flush-session", "--smart", "-u", endpoint])
        if parameter:
            cmd.extend(["-p", parameter])

        tech = (technique or "").lower()
        if tech == "enum":
            cmd.append("--dbs")
            timeout = 180
        elif tech == "exfil":
            cmd.append("--tables")
            timeout = 180
        elif tech == "escalate":
            # Keep escalate phase bounded to reconnaissance evidence.
            cmd.extend(["--current-user", "--hostname"])
            timeout = 120
        else:
            timeout = 120

        return EngineCommand(
            engine=self.name,
            command=cmd,
            timeout_sec=timeout,
            allow_network=True,
            metadata={"technique": tech or "unknown"},
        )


class ZapAdapter:
    name = "zaproxy"

    def supports(self, technique: str, command_template: str, vuln_type: str) -> bool:
        tmpl = (command_template or "").lower()
        return ("zaproxy" in tmpl) or ("zap" in tmpl)

    def required_dependencies(self) -> Sequence[str]:
        return ["zaproxy"]

    def build_command(
        self,
        technique: str,
        command_template: str,
        endpoint: str,
        parameter: str,
    ) -> Optional[EngineCommand]:
        if not endpoint:
            return None
        if not (shutil.which("zaproxy") or shutil.which("zap.sh") or shutil.which("zap.bat")):
            return None

        executable = "zaproxy" if shutil.which("zaproxy") else ("zap.bat" if shutil.which("zap.bat") else "zap.sh")
        cmd = [executable, "-cmd", "-quickurl", endpoint, "-quickprogress"]
        return EngineCommand(
            engine=self.name,
            command=cmd,
            timeout_sec=240,
            allow_network=True,
            metadata={"technique": (technique or "").lower() or "unknown"},
        )


class EngineAdapterRegistry:
    def __init__(self):
        self._adapters: List[EngineAdapter] = [SqlmapAdapter(), ZapAdapter()]

    def all_adapters(self) -> List[EngineAdapter]:
        return list(self._adapters)

    def find_adapter(self, technique: str, command_template: str, vuln_type: str) -> Optional[EngineAdapter]:
        for adapter in self._adapters:
            if adapter.supports(technique=technique, command_template=command_template, vuln_type=vuln_type):
                return adapter
        return None


_adapter_registry: Optional[EngineAdapterRegistry] = None


def get_engine_adapter_registry() -> EngineAdapterRegistry:
    global _adapter_registry
    if _adapter_registry is None:
        _adapter_registry = EngineAdapterRegistry()
    return _adapter_registry


"""Compatibility sandbox runner for offensive modules.

Canonical implementation lives in `backend/core/sandbox_runner.py`.
This module preserves the previous offensive API while delegating execution
to the core sandbox runner to keep a single runtime contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from backend.core.sandbox_runner import (
    SandboxConfig as CoreSandboxConfig,
    SandboxMode as CoreSandboxMode,
    SandboxRunner as CoreSandboxRunner,
)


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int = 0
    success: bool = False
    error: Optional[str] = None
    mode: str = "docker"


@dataclass
class SandboxConfig:
    image: str = "python:3.12-slim"
    memory_limit: str = "512m"
    cpu_limit: str = "0.5"
    network_mode: str = "none"  # 'none', 'host', or 'bridge'
    timeout_sec: int = 30
    user: str = "nobody"
    read_only: bool = True
    temp_dir: str = "/tmp/sandbox"


class SandboxRunner:
    """Offensive-facing runner API backed by the canonical core sandbox."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    def _to_core_runner(self, image: Optional[str], timeout_sec: Optional[int], allow_network: bool) -> CoreSandboxRunner:
        core_cfg = CoreSandboxConfig(
            mode=CoreSandboxMode.DOCKER,
            image=str(image or self.config.image),
            timeout_sec=max(1, int(timeout_sec or self.config.timeout_sec)),
            cpu_limit=str(self.config.cpu_limit),
            memory_limit=str(self.config.memory_limit),
            read_only=bool(self.config.read_only),
            network_mode=("bridge" if allow_network else "none"),
            mount_workspace=False,
        )
        return CoreSandboxRunner(core_cfg)

    async def run(
        self,
        command: Union[str, List[str]],
        image: Optional[str] = None,
        timeout_sec: Optional[int] = None,
        allow_network: bool = False,
        mounts: Optional[List[str]] = None,  # kept for API compatibility
        env_vars: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        # Preserve previous string-based API while supporting list commands too.
        if isinstance(command, str):
            run_cmd: List[str] = ["/bin/sh", "-c", command]
        else:
            run_cmd = [str(x) for x in command]

        # `mounts` is accepted for compatibility but intentionally ignored here.
        # Mount handling is centralized in core sandbox runner policy.
        _ = mounts

        runner = self._to_core_runner(image=image, timeout_sec=timeout_sec, allow_network=allow_network)
        core_res = await runner.run(
            command=run_cmd,
            timeout_sec=(timeout_sec or self.config.timeout_sec),
            allow_network=allow_network,
            extra_env=(env_vars or None),
        )
        return SandboxResult(
            exit_code=int(core_res.exit_code),
            stdout=str(core_res.stdout or ""),
            stderr=str(core_res.stderr or ""),
            duration_ms=int(core_res.duration_ms or 0),
            success=bool(core_res.success),
            error=(str(core_res.error) if core_res.error else None),
            mode=str(core_res.mode or "docker"),
        )


def get_sandbox_runner() -> SandboxRunner:
    return SandboxRunner()


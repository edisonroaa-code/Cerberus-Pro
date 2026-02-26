"""
Sandboxed command runner for chain execution.

Phase 3 objective:
- Run chain steps in isolated execution mode when possible (Docker).
- Keep deterministic local fallback for developer environments.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cerberus.sandbox_runner")


class SandboxMode(str, Enum):
    AUTO = "auto"
    DOCKER = "docker"
    LOCAL = "local"


@dataclass
class SandboxConfig:
    mode: SandboxMode = SandboxMode.AUTO
    image: str = "python:3.12-slim"
    timeout_sec: int = 120
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    pids_limit: int = 128
    read_only: bool = True
    network_mode: str = "bridge"
    mount_workspace: bool = True
    workspace_path: str = field(default_factory=lambda: str(Path(__file__).resolve().parents[2]))

    @classmethod
    def from_env(cls) -> "SandboxConfig":
        mode_raw = str(os.environ.get("CERBERUS_CHAIN_SANDBOX_MODE", "auto")).strip().lower()
        mode = SandboxMode.AUTO
        if mode_raw in ("docker", "local", "auto"):
            mode = SandboxMode(mode_raw)

        timeout_sec = int(os.environ.get("CERBERUS_CHAIN_SANDBOX_TIMEOUT_SEC", "120") or "120")
        pids_limit = int(os.environ.get("CERBERUS_CHAIN_SANDBOX_PIDS_LIMIT", "128") or "128")
        read_only = str(os.environ.get("CERBERUS_CHAIN_SANDBOX_READ_ONLY", "true")).strip().lower() in ("1", "true", "yes")
        mount_workspace = str(os.environ.get("CERBERUS_CHAIN_SANDBOX_MOUNT_WORKSPACE", "true")).strip().lower() in ("1", "true", "yes")

        return cls(
            mode=mode,
            image=str(os.environ.get("CERBERUS_CHAIN_SANDBOX_IMAGE", "python:3.12-slim")).strip(),
            timeout_sec=max(5, timeout_sec),
            cpu_limit=str(os.environ.get("CERBERUS_CHAIN_SANDBOX_CPUS", "1.0")).strip() or "1.0",
            memory_limit=str(os.environ.get("CERBERUS_CHAIN_SANDBOX_MEMORY", "512m")).strip() or "512m",
            pids_limit=max(32, pids_limit),
            read_only=read_only,
            network_mode=str(os.environ.get("CERBERUS_CHAIN_SANDBOX_NETWORK", "bridge")).strip() or "bridge",
            mount_workspace=mount_workspace,
            workspace_path=str(Path(os.environ.get("CERBERUS_CHAIN_SANDBOX_WORKSPACE", "")).resolve())
            if os.environ.get("CERBERUS_CHAIN_SANDBOX_WORKSPACE")
            else str(Path(__file__).resolve().parents[2]),
        )


@dataclass
class SandboxRunResult:
    success: bool
    mode: str
    command: List[str]
    exit_code: int
    duration_ms: int
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None


class SandboxRunner:
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig.from_env()

    def _docker_available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            proc = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def _select_mode(self) -> SandboxMode:
        if self.config.mode == SandboxMode.LOCAL:
            return SandboxMode.LOCAL
        if self.config.mode == SandboxMode.DOCKER:
            return SandboxMode.DOCKER
        return SandboxMode.DOCKER if self._docker_available() else SandboxMode.LOCAL

    def _docker_command(self, command: List[str], allow_network: bool) -> List[str]:
        docker_cmd: List[str] = [
            "docker",
            "run",
            "--rm",
            "--cpus",
            self.config.cpu_limit,
            "--memory",
            self.config.memory_limit,
            "--pids-limit",
            str(self.config.pids_limit),
            "--network",
            self.config.network_mode if allow_network else "none",
        ]
        if self.config.read_only:
            docker_cmd.append("--read-only")
        if self.config.mount_workspace:
            workspace = self.config.workspace_path
            docker_cmd.extend(["-v", f"{workspace}:/workspace"])
            docker_cmd.extend(["-w", "/workspace"])
        docker_cmd.append(self.config.image)
        docker_cmd.extend(command)
        return docker_cmd

    async def run(
        self,
        command: List[str],
        timeout_sec: Optional[int] = None,
        allow_network: bool = True,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> SandboxRunResult:
        selected_mode = self._select_mode()
        start = time.perf_counter()
        timeout = timeout_sec or self.config.timeout_sec

        if selected_mode == SandboxMode.DOCKER:
            docker_cmd = self._docker_command(command, allow_network=allow_network)
            result = await self._run_subprocess(
                docker_cmd,
                timeout_sec=timeout,
                mode=SandboxMode.DOCKER.value,
                extra_env=extra_env,
            )
            if result.success or self.config.mode == SandboxMode.DOCKER:
                return result
            logger.warning("[sandbox] Docker failed in AUTO mode, falling back to LOCAL. err=%s", result.error)

        local_result = await self._run_subprocess(
            command,
            timeout_sec=timeout,
            mode=SandboxMode.LOCAL.value,
            extra_env=extra_env,
        )
        local_result.duration_ms = int((time.perf_counter() - start) * 1000)
        return local_result

    async def _run_subprocess(
        self,
        command: List[str],
        timeout_sec: int,
        mode: str,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> SandboxRunResult:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        start = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return SandboxRunResult(
                    success=False,
                    mode=mode,
                    command=command,
                    exit_code=124,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    stdout="",
                    stderr="",
                    error=f"timeout ({timeout_sec}s)",
                )

            stdout = (stdout_b or b"").decode("utf-8", errors="replace")
            stderr = (stderr_b or b"").decode("utf-8", errors="replace")
            exit_code = int(proc.returncode or 0)
            return SandboxRunResult(
                success=(exit_code == 0),
                mode=mode,
                command=command,
                exit_code=exit_code,
                duration_ms=int((time.perf_counter() - start) * 1000),
                stdout=stdout[-4000:],
                stderr=stderr[-4000:],
                error=None if exit_code == 0 else f"exit_code={exit_code}",
            )
        except FileNotFoundError as exc:
            return SandboxRunResult(
                success=False,
                mode=mode,
                command=command,
                exit_code=127,
                duration_ms=int((time.perf_counter() - start) * 1000),
                stdout="",
                stderr="",
                error=str(exc),
            )
        except Exception as exc:
            return SandboxRunResult(
                success=False,
                mode=mode,
                command=command,
                exit_code=1,
                duration_ms=int((time.perf_counter() - start) * 1000),
                stdout="",
                stderr="",
                error=str(exc),
            )


_sandbox_runner: Optional[SandboxRunner] = None


def get_sandbox_runner() -> SandboxRunner:
    global _sandbox_runner
    if _sandbox_runner is None:
        _sandbox_runner = SandboxRunner()
    return _sandbox_runner


"""
Process and target-allowlist helpers extracted from ares_api.py.
"""

from __future__ import annotations

import ipaddress
import os
import signal
import subprocess
from typing import List, Optional, Sequence


def start_sqlmap_process(cmd: List[str], *, rlimit_cpu_seconds: int, rlimit_as_mb: int) -> subprocess.Popen:
    kwargs = dict(
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        def _set_limits():
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (rlimit_cpu_seconds, rlimit_cpu_seconds))
            max_bytes = int(rlimit_as_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))

        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _set_limits
    return subprocess.Popen(cmd, **kwargs)


def terminate_process_tree(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=3)
    except Exception:
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def normalize_host(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def host_allowed(host: str, allowed_targets: Sequence[str]) -> bool:
    if not allowed_targets:
        return True
    normalized_host = normalize_host(host)
    for entry in allowed_targets:
        allowed = normalize_host(str(entry or ""))
        if not allowed:
            continue
        if "/" in allowed:
            try:
                network = ipaddress.ip_network(allowed, strict=False)
                if is_ip(normalized_host) and ipaddress.ip_address(normalized_host) in network:
                    return True
                continue
            except Exception:
                pass
        if is_ip(allowed):
            if normalized_host == allowed:
                return True
            continue
        if normalized_host == allowed:
            return True
        if normalized_host.endswith(f".{allowed}"):
            return True
    return False

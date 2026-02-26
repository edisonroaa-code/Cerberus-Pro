import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.getcwd(), "backend"))

from core.sandbox_runner import SandboxConfig, SandboxMode, SandboxRunner


@pytest.mark.asyncio
async def test_sandbox_runner_local_exec_success():
    runner = SandboxRunner(
        SandboxConfig(
            mode=SandboxMode.LOCAL,
            timeout_sec=10,
        )
    )
    result = await runner.run([sys.executable, "-c", "print('sandbox-ok')"], timeout_sec=5)
    assert result.success is True
    assert result.mode == "local"
    assert "sandbox-ok" in result.stdout


@pytest.mark.asyncio
async def test_sandbox_runner_timeout():
    runner = SandboxRunner(
        SandboxConfig(
            mode=SandboxMode.LOCAL,
            timeout_sec=1,
        )
    )
    result = await runner.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout_sec=1)
    assert result.success is False
    assert result.exit_code == 124
    assert "timeout" in (result.error or "")


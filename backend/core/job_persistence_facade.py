import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from backend.core.job_persistence_runtime import (
    JobPersistenceRuntimeDeps,
    create_job as _create_job_impl,
    fallback_coverage_response_from_job as _fallback_coverage_response_from_job_impl,
    get_job as _get_job_impl,
    get_job_coverage_v1 as _get_job_coverage_v1_impl,
    list_jobs as _list_jobs_impl,
    update_job as _update_job_impl,
)


@dataclass
class JobPersistenceFacade:
    deps_factory: Callable[[], JobPersistenceRuntimeDeps]
    job_now_fn: Callable[[], str]

    async def create_job(
        self,
        *,
        scan_id: str,
        user_id: str,
        kind: str,
        status: str,
        phase: int,
        max_phase: int,
        autopilot: bool,
        target_url: str,
        cfg: dict,
        pid: Optional[int] = None,
        priority: int = 0,
    ) -> None:
        await asyncio.to_thread(
            _create_job_impl,
            scan_id=scan_id,
            user_id=user_id,
            kind=kind,
            status=status,
            phase=int(phase),
            max_phase=int(max_phase),
            autopilot=bool(autopilot),
            target_url=str(target_url),
            cfg=(cfg or {}),
            pid=pid,
            priority=int(priority),
            deps=self.deps_factory(),
            job_now_fn=self.job_now_fn,
        )

    async def update_job(self, scan_id: str, **fields: Any) -> None:
        await asyncio.to_thread(
            _update_job_impl,
            scan_id=str(scan_id),
            deps=self.deps_factory(),
            fields=(fields or {}),
        )

    async def get_job(self, scan_id: str) -> Optional[dict]:
        return await asyncio.to_thread(_get_job_impl, str(scan_id), deps=self.deps_factory())

    async def list_jobs(self, user_id: str, limit: int = 30) -> List[dict]:
        return await asyncio.to_thread(
            _list_jobs_impl, str(user_id), limit=int(limit), deps=self.deps_factory()
        )

    async def fallback_coverage_response_from_job(
        self,
        job: Dict[str, Any],
        scan_id: str,
        *,
        limit: int,
        cursor: int,
    ) -> Any:
        return await asyncio.to_thread(
            _fallback_coverage_response_from_job_impl,
            job=job,
            scan_id=str(scan_id),
            limit=int(limit),
            cursor=int(cursor),
            deps=self.deps_factory(),
        )

    async def get_job_coverage_v1(self, scan_id: str, *, limit: int, cursor: int) -> Any:
        return await asyncio.to_thread(
            _get_job_coverage_v1_impl,
            str(scan_id),
            limit=int(limit),
            cursor=int(cursor),
            deps=self.deps_factory(),
        )

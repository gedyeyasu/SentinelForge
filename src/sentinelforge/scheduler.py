from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelforge.control.models import (
    PentestRunRequest,
)
from sentinelforge.control.storage import SQLiteRunStore, utc_now
from sentinelforge.scope import ScopeValidationError, load_scope

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PentestSchedule:
    schedule_id: str
    repository: str
    scope_file: str
    mode: str
    interval_minutes: int
    enabled: bool
    created_at: str
    last_run_at: str | None
    next_run_at: str
    metadata_json: str = "{}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "repository": self.repository,
            "scope_file": self.scope_file,
            "mode": self.mode,
            "interval_minutes": self.interval_minutes,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "metadata": json.loads(self.metadata_json),
        }


class PentestScheduler:
    def __init__(
        self,
        store: SQLiteRunStore,
        *,
        check_interval_seconds: int = 30,
    ) -> None:
        self._store = store
        self._check_interval = check_interval_seconds
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._execute_fn: Any = None

    def set_executor(self, execute_fn: Any) -> None:
        self._execute_fn = execute_fn

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Pentest scheduler started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Pentest scheduler stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._tick()
            except Exception:
                logger.exception("Scheduler tick failed")
            await asyncio.sleep(self._check_interval)

    async def _tick(self) -> None:
        now = utc_now()
        schedules = self._store.list_pentest_schedules(
            enabled_only=True
        )
        for schedule in schedules:
            if schedule.next_run_at <= now:
                await self._run_schedule(schedule)

    async def _run_schedule(self, schedule: PentestSchedule) -> None:
        logger.info(
            "Executing scheduled pentest %s for %s",
            schedule.schedule_id,
            schedule.repository,
        )
        self._store.update_pentest_schedule(
            schedule.schedule_id,
            last_run_at=utc_now(),
            next_run_at=self._compute_next(
                schedule.interval_minutes
            ),
        )

        if self._execute_fn is None:
            logger.warning(
                "No executor configured for scheduler"
            )
            return

        try:
            scope_path = Path(schedule.scope_file)
            if not scope_path.is_file():
                logger.error(
                    "Scope file not found: %s", scope_path
                )
                return

            scope = load_scope(scope_path)
            request = PentestRunRequest(
                repository=schedule.repository,
                scope_file=schedule.scope_file,
            )

            await asyncio.to_thread(
                self._execute_fn, request, scope, schedule
            )
        except ScopeValidationError as exc:
            logger.error(
                "Scope validation failed for schedule %s: %s",
                schedule.schedule_id,
                exc,
            )
        except Exception:
            logger.exception(
                "Scheduled pentest failed for %s",
                schedule.schedule_id,
            )

    @staticmethod
    def _compute_next(interval_minutes: int) -> str:
        next_time = datetime.now(UTC) + timedelta(
            minutes=interval_minutes
        )
        return next_time.isoformat()

    def create_schedule(
        self,
        repository: str,
        scope_file: str,
        mode: str,
        interval_minutes: int,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> PentestSchedule:
        schedule_id = "sf_sched_" + uuid.uuid4().hex[:12]
        now = utc_now()
        next_run = self._compute_next(interval_minutes)
        meta_json = json.dumps(metadata or {})

        self._store.create_pentest_schedule(
            schedule_id=schedule_id,
            repository=repository,
            scope_file=scope_file,
            mode=mode,
            interval_minutes=interval_minutes,
            enabled=True,
            created_at=now,
            next_run_at=next_run,
            metadata_json=meta_json,
        )
        schedule = self._store.get_pentest_schedule(
            schedule_id
        )
        if schedule is None:
            raise RuntimeError(
                f"Schedule {schedule_id} was not persisted"
            )
        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        return self._store.delete_pentest_schedule(
            schedule_id
        )

    def list_schedules(
        self, *, enabled_only: bool = False
    ) -> list[PentestSchedule]:
        return self._store.list_pentest_schedules(
            enabled_only=enabled_only
        )

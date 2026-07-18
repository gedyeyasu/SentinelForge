from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.event_bus import EventBus, LiveEvent


@dataclass
class SwarmTask:
    """A single unit of attack work for one swarm worker."""

    task_id: str
    agent_role: str
    description: str
    target: str
    work: Callable[[], Any]


@dataclass
class SwarmTaskResult:
    task_id: str
    agent_role: str
    target: str
    status: str  # completed | failed
    result: Any = None
    error: str = ""
    duration_ms: int = 0


@dataclass
class SwarmResult:
    swarm_id: str
    total: int
    completed: int
    failed: int
    duration_s: float
    results: list[SwarmTaskResult] = field(default_factory=list)

    @property
    def outputs(self) -> list[Any]:
        return [r.result for r in self.results if r.status == "completed"]


class _RateLimiter:
    """Token-bucket rate limiter shared across all swarm workers."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 1.0 / max(requests_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next_at:
                await asyncio.sleep(self._next_at - now)
            self._next_at = max(time.monotonic(), self._next_at) + self._interval


class AgentSwarm:
    """Parallel multi-agent attack execution engine.

    Spawns up to ``max_concurrency`` concurrent workers, each executing an
    attack task against the authorized target. Every spawn/completion emits
    a LiveEvent so the dashboard shows agents appearing and reporting in
    real time. Respects the scope rate budget via a shared token bucket and
    honors the kill switch between tasks.
    """

    def __init__(
        self,
        *,
        run_id: str,
        bus: EventBus,
        phase: str,
        max_concurrency: int = 4,
        requests_per_second: float = 3.0,
        kill_switch_file: str = "/run/sentinelforge/STOP",
    ) -> None:
        self.run_id = run_id
        self._bus = bus
        self._phase = phase
        self._sem = asyncio.Semaphore(max_concurrency)
        self._limiter = _RateLimiter(requests_per_second)
        self._kill_switch_file = kill_switch_file
        self.swarm_id = "swarm_" + uuid.uuid4().hex[:8]
        self._max_concurrency = max_concurrency

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        self._bus.publish(
            LiveEvent(
                run_id=self.run_id,
                phase=self._phase,
                kind=kind,
                timestamp=time.time(),
                payload=payload,
            )
        )

    def _killed(self) -> bool:
        from pathlib import Path

        return Path(self._kill_switch_file).exists()

    async def _run_one(self, task: SwarmTask) -> SwarmTaskResult:
        async with self._sem:
            if self._killed():
                return SwarmTaskResult(
                    task_id=task.task_id,
                    agent_role=task.agent_role,
                    target=task.target,
                    status="failed",
                    error="kill_switch_engaged",
                )
            self._emit(
                "swarm_agent_spawned",
                {
                    "agent": task.agent_role,
                    "swarm_id": self.swarm_id,
                    "task_id": task.task_id,
                    "target": task.target,
                    "message": f"Spawned {task.agent_role}: {task.description}",
                },
            )
            started = time.monotonic()
            try:
                await self._limiter.acquire()
                result = await asyncio.to_thread(task.work)
                duration_ms = int((time.monotonic() - started) * 1000)
                self._emit(
                    "swarm_agent_completed",
                    {
                        "agent": task.agent_role,
                        "swarm_id": self.swarm_id,
                        "task_id": task.task_id,
                        "target": task.target,
                        "duration_ms": duration_ms,
                        "message": (
                            f"{task.agent_role} finished {task.target} "
                            f"in {duration_ms}ms"
                        ),
                    },
                )
                return SwarmTaskResult(
                    task_id=task.task_id,
                    agent_role=task.agent_role,
                    target=task.target,
                    status="completed",
                    result=result,
                    duration_ms=duration_ms,
                )
            except Exception as error:
                duration_ms = int((time.monotonic() - started) * 1000)
                self._emit(
                    "swarm_agent_failed",
                    {
                        "agent": task.agent_role,
                        "swarm_id": self.swarm_id,
                        "task_id": task.task_id,
                        "target": task.target,
                        "error": str(error)[:300],
                        "message": f"{task.agent_role} failed: {error}",
                    },
                )
                return SwarmTaskResult(
                    task_id=task.task_id,
                    agent_role=task.agent_role,
                    target=task.target,
                    status="failed",
                    error=str(error)[:500],
                    duration_ms=duration_ms,
                )

    async def execute(self, tasks: list[SwarmTask]) -> SwarmResult:
        """Run all tasks concurrently (bounded) and aggregate results."""
        self._emit(
            "swarm_launched",
            {
                "agent": "SwarmCoordinator",
                "swarm_id": self.swarm_id,
                "worker_count": min(len(tasks), self._max_concurrency),
                "task_count": len(tasks),
                "message": (
                    f"Swarm {self.swarm_id} launching "
                    f"{len(tasks)} attack agents "
                    f"(max {self._max_concurrency} concurrent)"
                ),
            },
        )
        started = time.monotonic()
        results = await asyncio.gather(
            *(self._run_one(task) for task in tasks)
        )
        duration_s = round(time.monotonic() - started, 2)
        completed = sum(1 for r in results if r.status == "completed")
        failed = len(results) - completed
        self._emit(
            "swarm_finished",
            {
                "agent": "SwarmCoordinator",
                "swarm_id": self.swarm_id,
                "total": len(results),
                "completed": completed,
                "failed": failed,
                "duration_s": duration_s,
                "message": (
                    f"Swarm {self.swarm_id} done: {completed}/{len(results)} "
                    f"agents completed in {duration_s}s"
                ),
            },
        )
        return SwarmResult(
            swarm_id=self.swarm_id,
            total=len(results),
            completed=completed,
            failed=failed,
            duration_s=duration_s,
            results=list(results),
        )

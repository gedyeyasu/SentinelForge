from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class ScanStatus(StrEnum):
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class ScanResult:
    scan_id: str
    target: str
    status: ScanStatus
    started_at: float
    completed_at: float | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "finding_count": len(self.findings),
            "metadata": self.metadata,
        }


class ContinuousScanner:
    """Manages scheduled continuous security scans.

    Tracks scan history, manages intervals, and provides
    reporting on scan coverage and findings.
    """

    def __init__(
        self,
        *,
        default_interval_minutes: int = 60,
        max_concurrent_scans: int = 3,
    ) -> None:
        self._default_interval = default_interval_minutes
        self._max_concurrent = max_concurrent_scans
        self._schedules: dict[str, dict[str, Any]] = {}
        self._scan_history: list[ScanResult] = []
        self._active_scans: dict[str, ScanResult] = {}

    def create_schedule(
        self,
        target: str,
        interval_minutes: int | None = None,
        mode: str = "standard",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        import uuid

        schedule_id = "sched_" + uuid.uuid4().hex[:12]
        interval = interval_minutes or self._default_interval

        schedule = {
            "schedule_id": schedule_id,
            "target": target,
            "interval_minutes": interval,
            "mode": mode,
            "enabled": True,
            "created_at": time.time(),
            "last_run_at": None,
            "next_run_at": time.time() + (interval * 60),
            "metadata": metadata or {},
        }
        self._schedules[schedule_id] = schedule
        return schedule

    def update_schedule(
        self,
        schedule_id: str,
        *,
        interval_minutes: int | None = None,
        enabled: bool | None = None,
        mode: str | None = None,
    ) -> dict[str, Any] | None:
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return None

        if interval_minutes is not None:
            schedule["interval_minutes"] = interval_minutes
            schedule["next_run_at"] = time.time() + (interval_minutes * 60)
        if enabled is not None:
            schedule["enabled"] = enabled
        if mode is not None:
            schedule["mode"] = mode

        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            return True
        return False

    def list_schedules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        schedules = list(self._schedules.values())
        if enabled_only:
            schedules = [s for s in schedules if s["enabled"]]
        return schedules

    def get_due_schedules(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            s for s in self._schedules.values()
            if s["enabled"] and s["next_run_at"] <= now
        ]

    def mark_scan_started(self, schedule_id: str, target: str) -> ScanResult | None:
        schedule = self._schedules.get(schedule_id)
        if schedule is None:
            return None

        if len(self._active_scans) >= self._max_concurrent:
            logger.warning("Max concurrent scans reached, skipping %s", schedule_id)
            return None

        import uuid

        scan = ScanResult(
            scan_id="scan_" + uuid.uuid4().hex[:12],
            target=target,
            status=ScanStatus.SCANNING,
            started_at=time.time(),
            metadata={"schedule_id": schedule_id, "mode": schedule["mode"]},
        )
        self._active_scans[scan.scan_id] = scan
        return scan

    def mark_scan_completed(
        self,
        scan_id: str,
        findings: list[dict[str, Any]] | None = None,
    ) -> ScanResult | None:
        scan = self._active_scans.pop(scan_id, None)
        if scan is None:
            return None

        scan.status = ScanStatus.IDLE
        scan.completed_at = time.time()
        if findings:
            scan.findings = findings

        self._scan_history.append(scan)

        schedule_id = scan.metadata.get("schedule_id", "")
        schedule = self._schedules.get(schedule_id)
        if schedule:
            schedule["last_run_at"] = time.time()
            schedule["next_run_at"] = time.time() + (schedule["interval_minutes"] * 60)

        return scan

    def get_scan_history(
        self, target: str | None = None, limit: int = 50
    ) -> list[ScanResult]:
        history = self._scan_history
        if target:
            history = [s for s in history if s.target == target]
        return history[-limit:]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_schedules": len(self._schedules),
            "active_schedules": sum(1 for s in self._schedules.values() if s["enabled"]),
            "active_scans": len(self._active_scans),
            "total_history": len(self._scan_history),
            "findings_total": sum(len(s.findings) for s in self._scan_history),
        }

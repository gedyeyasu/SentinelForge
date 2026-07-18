from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sentinelforge.control.models import (
    IntegrationHealth,
    PentestPhase,
    PentestRunRecord,
    PentestRunRequest,
    PentestScheduleRecord,
    PentestStatus,
    RunEvent,
    RunLifecycle,
    RunRecord,
    SecurityVerdict,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class SQLiteRunStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    candidate_verdict TEXT NOT NULL,
                    patch_verdict TEXT NOT NULL,
                    integration_health TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS events_run_sequence
                ON events(run_id, sequence);

                CREATE TABLE IF NOT EXISTS pentest_runs (
                    run_id TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    scope_file TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    candidate_verdict TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'standard',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    results_json TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS pentest_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    repository TEXT NOT NULL,
                    scope_file TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'standard',
                    interval_minutes INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_run_at TEXT,
                    next_run_at TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}'
                );
                """
            )

    def create_run(self, run_id: str, repository: Path) -> RunRecord:
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, repository, lifecycle, candidate_verdict, patch_verdict,
                    integration_health, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(repository),
                    RunLifecycle.QUEUED.value,
                    SecurityVerdict.PENDING.value,
                    SecurityVerdict.PENDING.value,
                    IntegrationHealth.HEALTHY.value,
                    now,
                    now,
                ),
            )
        record = self.get_run(run_id)
        if record is None:
            raise RuntimeError(f"Run {run_id} was not persisted")
        return record

    def update_run(
        self,
        run_id: str,
        *,
        lifecycle: RunLifecycle | None = None,
        candidate_verdict: SecurityVerdict | None = None,
        patch_verdict: SecurityVerdict | None = None,
        integration_health: IntegrationHealth | None = None,
        result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> RunRecord:
        current = self.get_run(run_id)
        if current is None:
            raise KeyError(run_id)
        next_record = current.model_copy(
            update={
                "lifecycle": lifecycle or current.lifecycle,
                "candidate_verdict": candidate_verdict or current.candidate_verdict,
                "patch_verdict": patch_verdict or current.patch_verdict,
                "integration_health": integration_health or current.integration_health,
                "result": result if result is not None else current.result,
                "error": error,
                "updated_at": utc_now(),
            }
        )
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE runs SET lifecycle = ?, candidate_verdict = ?, patch_verdict = ?,
                    integration_health = ?, updated_at = ?, result_json = ?, error = ?
                WHERE run_id = ?
                """,
                (
                    next_record.lifecycle.value,
                    next_record.candidate_verdict.value,
                    next_record.patch_verdict.value,
                    next_record.integration_health.value,
                    next_record.updated_at,
                    json.dumps(next_record.result) if next_record.result is not None else None,
                    next_record.error,
                    run_id,
                ),
            )
        return next_record

    def append_event(
        self, run_id: str, *, phase: str, kind: str, payload: dict[str, object]
    ) -> RunEvent:
        occurred_at = utc_now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events (run_id, phase, kind, occurred_at, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, phase, kind, occurred_at, json.dumps(payload, sort_keys=True)),
            )
            sequence = int(cursor.lastrowid)
        return RunEvent(
            sequence=sequence,
            run_id=run_id,
            phase=phase,
            kind=kind,
            occurred_at=occurred_at,
            payload=payload,
        )

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return self._record(row)

    def list_events(self, run_id: str, after: int = 0) -> list[RunEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE run_id = ? AND sequence > ? ORDER BY sequence",
                (run_id, after),
            ).fetchall()
        return [
            RunEvent(
                sequence=int(row["sequence"]),
                run_id=str(row["run_id"]),
                phase=str(row["phase"]),
                kind=str(row["kind"]),
                occurred_at=str(row["occurred_at"]),
                payload=json.loads(str(row["payload_json"])),
            )
            for row in rows
        ]

    @staticmethod
    def _record(row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            run_id=str(row["run_id"]),
            repository=str(row["repository"]),
            lifecycle=RunLifecycle(str(row["lifecycle"])),
            candidate_verdict=SecurityVerdict(str(row["candidate_verdict"])),
            patch_verdict=SecurityVerdict(str(row["patch_verdict"])),
            integration_health=IntegrationHealth(str(row["integration_health"])),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            result=json.loads(str(row["result_json"])) if row["result_json"] else None,
            error=str(row["error"]) if row["error"] else None,
        )

    def create_pentest_run(
        self, run_id: str, request: PentestRunRequest
    ) -> PentestRunRecord:
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pentest_runs (
                    run_id, repository, scope_file, status, phase,
                    candidate_verdict, mode, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    request.repository,
                    request.scope_file,
                    PentestStatus.QUEUED.value,
                    PentestPhase.SCOPING.value,
                    SecurityVerdict.PENDING.value,
                    request.mode.value,
                    now,
                    now,
                ),
            )
        record = self.get_pentest_run(run_id)
        if record is None:
            raise RuntimeError(f"Pentest run {run_id} was not persisted")
        return record

    def update_pentest_run(
        self,
        run_id: str,
        *,
        status: PentestStatus | None = None,
        phase: PentestPhase | None = None,
        candidate_verdict: SecurityVerdict | None = None,
        results: dict[str, object] | None = None,
        error: str | None = None,
    ) -> PentestRunRecord:
        current = self.get_pentest_run(run_id)
        if current is None:
            raise KeyError(run_id)
        next_record = current.model_copy(
            update={
                "status": status or current.status,
                "phase": phase or current.phase,
                "candidate_verdict": candidate_verdict or current.candidate_verdict,
                "results": results if results is not None else current.results,
                "error": error,
                "updated_at": utc_now(),
            }
        )
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE pentest_runs SET status = ?, phase = ?, candidate_verdict = ?,
                    updated_at = ?, results_json = ?, error = ?
                WHERE run_id = ?
                """,
                (
                    next_record.status.value,
                    next_record.phase.value,
                    next_record.candidate_verdict.value,
                    next_record.updated_at,
                    json.dumps(next_record.results) if next_record.results is not None else None,
                    next_record.error,
                    run_id,
                ),
            )
        return next_record

    def get_pentest_run(self, run_id: str) -> PentestRunRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pentest_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        return PentestRunRecord(
            run_id=str(row["run_id"]),
            repository=str(row["repository"]),
            scope_file=str(row["scope_file"]),
            status=PentestStatus(str(row["status"])),
            phase=PentestPhase(str(row["phase"])),
            candidate_verdict=SecurityVerdict(str(row["candidate_verdict"])),
            mode=str(row["mode"]) if "mode" in row.keys() else "standard",
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            results=json.loads(str(row["results_json"])) if row["results_json"] else None,
            error=str(row["error"]) if row["error"] else None,
        )

    def list_pentest_runs(
        self, *, limit: int = 50, offset: int = 0
    ) -> list[PentestRunRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pentest_runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._pentest_record(row) for row in rows]

    @staticmethod
    def _pentest_record(row: sqlite3.Row) -> PentestRunRecord:
        return PentestRunRecord(
            run_id=str(row["run_id"]),
            repository=str(row["repository"]),
            scope_file=str(row["scope_file"]),
            status=PentestStatus(str(row["status"])),
            phase=PentestPhase(str(row["phase"])),
            candidate_verdict=SecurityVerdict(str(row["candidate_verdict"])),
            mode=str(row["mode"]) if "mode" in row.keys() else "standard",
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            results=json.loads(str(row["results_json"])) if row["results_json"] else None,
            error=str(row["error"]) if row["error"] else None,
        )

    def create_pentest_schedule(
        self,
        schedule_id: str,
        repository: str,
        scope_file: str,
        mode: str,
        interval_minutes: int,
        enabled: bool,
        created_at: str,
        next_run_at: str,
        metadata_json: str = "{}",
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pentest_schedules (
                    schedule_id, repository, scope_file, mode,
                    interval_minutes, enabled, created_at, next_run_at,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule_id,
                    repository,
                    scope_file,
                    mode,
                    interval_minutes,
                    1 if enabled else 0,
                    created_at,
                    next_run_at,
                    metadata_json,
                ),
            )

    def get_pentest_schedule(
        self, schedule_id: str
    ) -> PentestScheduleRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pentest_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
        if row is None:
            return None
        return self._schedule_record(row)

    def list_pentest_schedules(
        self, *, enabled_only: bool = False
    ) -> list[PentestScheduleRecord]:
        query = "SELECT * FROM pentest_schedules"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY next_run_at"
        with self._connect() as connection:
            rows = connection.execute(query).fetchall()
        return [self._schedule_record(row) for row in rows]

    def update_pentest_schedule(
        self,
        schedule_id: str,
        *,
        enabled: bool | None = None,
        last_run_at: str | None = None,
        next_run_at: str | None = None,
    ) -> None:
        updates: list[str] = []
        values: list[object] = []
        if enabled is not None:
            updates.append("enabled = ?")
            values.append(1 if enabled else 0)
        if last_run_at is not None:
            updates.append("last_run_at = ?")
            values.append(last_run_at)
        if next_run_at is not None:
            updates.append("next_run_at = ?")
            values.append(next_run_at)
        if not updates:
            return
        values.append(schedule_id)
        with self._connect() as connection:
            connection.execute(
                f"UPDATE pentest_schedules SET {', '.join(updates)} WHERE schedule_id = ?",
                values,
            )

    def delete_pentest_schedule(self, schedule_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM pentest_schedules WHERE schedule_id = ?",
                (schedule_id,),
            )
            return cursor.rowcount > 0

    @staticmethod
    def _schedule_record(row: sqlite3.Row) -> PentestScheduleRecord:
        return PentestScheduleRecord(
            schedule_id=str(row["schedule_id"]),
            repository=str(row["repository"]),
            scope_file=str(row["scope_file"]),
            mode=str(row["mode"]),
            interval_minutes=int(row["interval_minutes"]),
            enabled=bool(row["enabled"]),
            created_at=str(row["created_at"]),
            last_run_at=str(row["last_run_at"]) if row["last_run_at"] else None,
            next_run_at=str(row["next_run_at"]),
            metadata=json.loads(str(row["metadata_json"])) if row["metadata_json"] else {},
        )

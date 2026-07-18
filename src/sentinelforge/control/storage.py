from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from sentinelforge.control.models import (
    IntegrationHealth,
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
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    phase TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS events_run_sequence
                ON events(run_id, sequence);
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

from __future__ import annotations

import json
import sqlite3
import threading
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
        self._write_lock = threading.RLock()
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
                    target_type TEXT NOT NULL DEFAULT 'local',
                    staging_url TEXT NOT NULL DEFAULT '',
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

                CREATE TABLE IF NOT EXISTS security_invariants (
                    id TEXT PRIMARY KEY,
                    invariant TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'active',
                    metadata_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS target_memory (
                    target_id TEXT PRIMARY KEY,
                    base_url TEXT NOT NULL,
                    endpoint_map_json TEXT NOT NULL DEFAULT '[]',
                    role_graph_json TEXT NOT NULL DEFAULT '{}',
                    login_workflow_json TEXT NOT NULL DEFAULT '{}',
                    prior_attacks_json TEXT NOT NULL DEFAULT '[]',
                    successful_payloads_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL,
                    run_count INTEGER NOT NULL DEFAULT 1,
                    learning_delta_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS advisory_cursor (
                    id TEXT PRIMARY KEY,
                    last_timestamp TEXT NOT NULL,
                    dedup_key TEXT NOT NULL,
                    advisory_count INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT 'redhat_csaf',
                    payload_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_traces (
                    trace_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    agent_role TEXT NOT NULL,
                    model TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    prompt_template_version TEXT NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    latency_ms INTEGER,
                    retry_count INTEGER DEFAULT 0,
                    hiddenlayer_input_verdict TEXT,
                    hiddenlayer_output_verdict TEXT,
                    tool_call_parse_success INTEGER DEFAULT 1,
                    cost_usd REAL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS traces_run_idx ON agent_traces(run_id);
                CREATE INDEX IF NOT EXISTS traces_role_idx ON agent_traces(agent_role);
                """
            )
            for col, default in [
                ("target_type", "'local'"),
                ("staging_url", "''"),
            ]:
                try:
                    connection.execute(
                        f"ALTER TABLE pentest_runs ADD COLUMN {col} "
                        f"TEXT NOT NULL DEFAULT {default}"
                    )
                except sqlite3.OperationalError:
                    pass

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
                    candidate_verdict, mode, target_type, staging_url,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    request.repository,
                    request.scope_file,
                    PentestStatus.QUEUED.value,
                    PentestPhase.SCOPING.value,
                    SecurityVerdict.PENDING.value,
                    request.mode.value,
                    request.target_type,
                    request.staging_url,
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
        with self._write_lock:
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
            target_type=(
                str(row["target_type"])
                if "target_type" in row.keys() else "local"
            ),
            staging_url=(
                str(row["staging_url"])
                if "staging_url" in row.keys() else ""
            ),
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
                """
                SELECT run_id, repository, scope_file, status, phase,
                    candidate_verdict, mode, target_type, staging_url,
                    created_at, updated_at, NULL AS results_json, error
                FROM pentest_runs
                ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
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
            target_type=(
                str(row["target_type"])
                if "target_type" in row.keys() else "local"
            ),
            staging_url=(
                str(row["staging_url"])
                if "staging_url" in row.keys() else ""
            ),
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

    # --- Enterprise learning tables ---

    def upsert_security_invariant(
        self,
        invariant_id: str,
        invariant: str,
        file_path: str,
        rule_id: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT count FROM security_invariants WHERE id = ?", (invariant_id,)
            ).fetchone()
            if row:
                connection.execute(
                    "UPDATE security_invariants SET last_seen = ?, count = count + 1, metadata_json = ? WHERE id = ?",
                    (now, json.dumps(metadata or {}, sort_keys=True), invariant_id),
                )
            else:
                connection.execute(
                    "INSERT INTO security_invariants (id, invariant, file_path, rule_id, first_seen, last_seen, count, status, metadata_json) VALUES (?, ?, ?, ?, ?, ?, 1, 'active', ?)",
                    (invariant_id, invariant, file_path, rule_id, now, now, json.dumps(metadata or {}, sort_keys=True)),
                )

    def list_security_invariants(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_invariants ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_target_memory(
        self,
        target_id: str,
        base_url: str,
        endpoint_map: list[dict[str, object]],
        role_graph: dict[str, object],
        prior_attacks: list[dict[str, object]],
        learning_delta: dict[str, object] | None = None,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT run_count FROM target_memory WHERE target_id = ?", (target_id,)
            ).fetchone()
            if existing:
                connection.execute(
                    "UPDATE target_memory SET endpoint_map_json = ?, role_graph_json = ?, prior_attacks_json = ?, learning_delta_json = ?, updated_at = ?, run_count = run_count + 1 WHERE target_id = ?",
                    (
                        json.dumps(endpoint_map, sort_keys=True),
                        json.dumps(role_graph, sort_keys=True),
                        json.dumps(prior_attacks, sort_keys=True),
                        json.dumps(learning_delta or {}, sort_keys=True),
                        now,
                        target_id,
                    ),
                )
            else:
                connection.execute(
                    "INSERT INTO target_memory (target_id, base_url, endpoint_map_json, role_graph_json, login_workflow_json, prior_attacks_json, successful_payloads_json, updated_at, run_count, learning_delta_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                    (
                        target_id,
                        base_url,
                        json.dumps(endpoint_map, sort_keys=True),
                        json.dumps(role_graph, sort_keys=True),
                        json.dumps({}, sort_keys=True),
                        json.dumps(prior_attacks, sort_keys=True),
                        json.dumps([], sort_keys=True),
                        now,
                        json.dumps(learning_delta or {}, sort_keys=True),
                    ),
                )

    def get_target_memory(self, target_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM target_memory WHERE target_id = ?", (target_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def upsert_advisory_cursor(
        self,
        cursor_id: str,
        last_timestamp: str,
        dedup_key: str,
        advisory_count: int,
        source: str = "redhat_csaf",
        payload: dict[str, object] | None = None,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            existing = connection.execute("SELECT id FROM advisory_cursor WHERE id = ?", (cursor_id,)).fetchone()
            if existing:
                connection.execute(
                    "UPDATE advisory_cursor SET last_timestamp = ?, dedup_key = ?, advisory_count = ?, payload_json = ?, updated_at = ? WHERE id = ?",
                    (
                        last_timestamp,
                        dedup_key,
                        advisory_count,
                        json.dumps(payload or {}, sort_keys=True),
                        now,
                        cursor_id,
                    ),
                )
            else:
                connection.execute(
                    "INSERT INTO advisory_cursor (id, last_timestamp, dedup_key, advisory_count, source, payload_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        cursor_id,
                        last_timestamp,
                        dedup_key,
                        advisory_count,
                        source,
                        json.dumps(payload or {}, sort_keys=True),
                        now,
                        now,
                    ),
                )

    def get_advisory_cursor(self, cursor_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM advisory_cursor WHERE id = ?", (cursor_id,)).fetchone()
        return dict(row) if row else None

    def append_agent_trace(
        self,
        trace_id: str,
        run_id: str,
        agent_role: str,
        model: str,
        provider: str,
        prompt_template_version: str = "v1",
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        latency_ms: int | None = None,
        retry_count: int = 0,
        hiddenlayer_input_verdict: str | None = None,
        hiddenlayer_output_verdict: str | None = None,
        tool_call_parse_success: bool = True,
        cost_usd: float | None = None,
        payload: dict[str, object] | None = None,
    ) -> None:
        import uuid as _uuid

        if not trace_id:
            trace_id = _uuid.uuid4().hex
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO agent_traces (trace_id, run_id, agent_role, model, provider, prompt_template_version, input_tokens, output_tokens, latency_ms, retry_count, hiddenlayer_input_verdict, hiddenlayer_output_verdict, tool_call_parse_success, cost_usd, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    trace_id,
                    run_id,
                    agent_role,
                    model,
                    provider,
                    prompt_template_version,
                    input_tokens,
                    output_tokens,
                    latency_ms,
                    retry_count,
                    hiddenlayer_input_verdict,
                    hiddenlayer_output_verdict,
                    1 if tool_call_parse_success else 0,
                    cost_usd,
                    now,
                    json.dumps(payload or {}, sort_keys=True),
                ),
            )

    def list_agent_traces(self, run_id: str) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM agent_traces WHERE run_id = ? ORDER BY created_at", (run_id,)
            ).fetchall()
        return [dict(r) for r in rows]

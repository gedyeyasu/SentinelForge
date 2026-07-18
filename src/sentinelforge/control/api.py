from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import (
    DetectionRunRequest,
    PentestMode,
    PentestRunRequest,
    RunEvent,
    RunRecord,
)
from sentinelforge.control.service import DetectionRunService, RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.integrations import RedHatAdvisory, RedHatSecurityDataClient
from sentinelforge.pentest import PentestService
from sentinelforge.pentest_modes import list_modes
from sentinelforge.scheduler import PentestScheduler
from sentinelforge.scope import ScopeValidationError, load_scope


def create_app(
    *,
    database_path: Path,
    workspace_root: Path,
    allowed_roots: tuple[Path, ...],
) -> FastAPI:
    service = DetectionRunService(
        SQLiteRunStore(database_path),
        workspace_root=workspace_root,
        allowed_roots=allowed_roots,
    )
    pentest_service = PentestService(service.store)
    scheduler = PentestScheduler(service.store)
    app = FastAPI(title="SentinelForge Control Plane", version="0.2.0")
    static_root = Path(__file__).parents[1] / "web" / "static"
    app.mount("/assets", StaticFiles(directory=static_root), name="assets")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(static_root / "index.html")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/integrations")
    def integrations() -> dict[str, dict[str, object]]:
        nvidia = resolve_nvidia_config()
        return {
            "deterministic": {"status": "active"},
            "nvidia_nim": {
                "status": "configured" if nvidia.configured else "awaiting_key",
                "model": nvidia.model,
            },
            "red_hat_security_data": {"status": "public_api"},
            "hiddenlayer": {
                "status": (
                    "configured" if os.environ.get("HIDDENLAYER_API_KEY") else "awaiting_key"
                )
            },
            "pentest_scheduler": {"status": "active"},
        }

    @app.get("/api/intelligence/redhat", response_model=list[RedHatAdvisory])
    def red_hat_intelligence(
        package: str | None = Query(default=None, min_length=1, max_length=80),
        days: int = Query(default=30, ge=1, le=365),
        limit: int = Query(default=10, ge=1, le=25),
    ) -> list[RedHatAdvisory]:
        try:
            return RedHatSecurityDataClient().list_advisories(
                package=package,
                created_days_ago=days,
                per_page=limit,
            )
        except (httpx.HTTPError, ValueError) as error:
            raise HTTPException(
                status_code=502, detail="Red Hat security data unavailable"
            ) from error

    @app.post("/api/runs", response_model=RunRecord, status_code=202)
    def create_run(request: DetectionRunRequest, tasks: BackgroundTasks) -> RunRecord:
        try:
            run = service.create(Path(request.repository))
        except RepositoryNotAuthorizedError as error:
            raise HTTPException(status_code=403, detail=str(error)) from error
        tasks.add_task(service.execute, run.run_id, request.remediate)
        return run

    @app.get("/api/runs/{run_id}", response_model=RunRecord)
    def get_run(run_id: str) -> RunRecord:
        run = service.store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @app.get("/api/runs/{run_id}/events", response_model=list[RunEvent])
    def list_events(run_id: str, after: int = Query(default=0, ge=0)) -> list[RunEvent]:
        if service.store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return service.store.list_events(run_id, after=after)

    @app.post("/api/pentest")
    def create_pentest(request: PentestRunRequest) -> dict[str, object]:
        scope_path = Path(request.scope_file)
        if not scope_path.is_file():
            raise HTTPException(
                status_code=400,
                detail=f"Scope file not found: {scope_path}",
            )
        try:
            scope = load_scope(scope_path)
        except ScopeValidationError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        try:
            result = pentest_service.create_and_execute(request, scope=scope)
        except Exception as error:
            raise HTTPException(status_code=500, detail=str(error)) from error
        return result

    @app.get("/api/pentest")
    def list_pentest_runs(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, object]:
        runs = service.store.list_pentest_runs(limit=limit, offset=offset)
        return {
            "runs": [r.model_dump() for r in runs],
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/pentest/{run_id}")
    def get_pentest_run(run_id: str) -> dict[str, object]:
        pentest = service.store.get_pentest_run(run_id)
        if pentest is None:
            raise HTTPException(status_code=404, detail="Pentest run not found")
        events = service.store.list_events(run_id)
        return {
            "pentest_run": pentest.model_dump(),
            "events": [e.model_dump() for e in events],
        }

    @app.get("/api/pentest/{run_id}/events")
    def list_pentest_events(
        run_id: str, after: int = Query(default=0, ge=0)
    ) -> list[RunEvent]:
        if service.store.get_pentest_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Pentest run not found")
        return service.store.list_events(run_id, after=after)

    @app.get("/api/pentest/modes")
    def pentest_modes() -> list[dict[str, object]]:
        return list_modes()

    @app.post("/api/pentest/schedule")
    def create_pentest_schedule(
        repository: str = Query(min_length=1),
        scope_file: str = Query(default="config/scope.yaml"),
        mode: str = Query(default="standard"),
        interval_minutes: int = Query(ge=5, le=1440, default=60),
    ) -> dict[str, object]:
        scope_path = Path(scope_file)
        if not scope_path.is_file():
            raise HTTPException(
                status_code=400,
                detail=f"Scope file not found: {scope_path}",
            )
        try:
            PentestMode(mode)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode: {mode}. "
                f"Valid: {', '.join(m.value for m in PentestMode)}",
            ) from None
        schedule = scheduler.create_schedule(
            repository=repository,
            scope_file=scope_file,
            mode=mode,
            interval_minutes=interval_minutes,
        )
        return schedule.model_dump()

    @app.get("/api/pentest/schedule")
    def list_pentest_schedules() -> dict[str, object]:
        schedules = scheduler.list_schedules()
        return {
            "schedules": [s.model_dump() for s in schedules],
        }

    @app.delete("/api/pentest/schedule/{schedule_id}")
    def delete_pentest_schedule(schedule_id: str) -> dict[str, str]:
        deleted = scheduler.delete_schedule(schedule_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return {"status": "deleted", "schedule_id": schedule_id}

    return app

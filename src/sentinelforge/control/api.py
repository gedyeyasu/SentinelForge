from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import DetectionRunRequest, RunEvent, RunRecord
from sentinelforge.control.service import DetectionRunService, RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.integrations import RedHatAdvisory, RedHatSecurityDataClient


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
    app = FastAPI(title="SentinelForge Control Plane", version="0.1.0")
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

    return app

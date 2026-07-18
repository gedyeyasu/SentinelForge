from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from sentinelforge.control import create_app


def application_from_environment() -> FastAPI:
    repository_root = Path.cwd().resolve()
    configured = os.environ.get("SENTINELFORGE_ALLOWED_ROOTS")
    allowed_roots = (
        tuple(Path(value) for value in configured.split(os.pathsep) if value)
        if configured
        else (repository_root,)
    )
    state_root = Path(os.environ.get("SENTINELFORGE_STATE_ROOT", ".sentinelforge/control"))
    return create_app(
        database_path=state_root / "runs.sqlite3",
        workspace_root=state_root / "workspaces",
        allowed_roots=allowed_roots,
    )


app = application_from_environment()


def main() -> None:
    uvicorn.run("sentinelforge.server:app", host="127.0.0.1", port=8741, reload=False)

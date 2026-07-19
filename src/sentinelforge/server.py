from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
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
    db_path_env = os.environ.get("SENTINELFORGE_DB_PATH", "").strip()
    if db_path_env:
        database_path = Path(db_path_env)
        state_root = database_path.parent
    else:
        state_root = Path(
            os.environ.get("SENTINELFORGE_STATE_ROOT", ".sentinelforge/control")
        )
        database_path = state_root / "runs.sqlite3"
    return create_app(
        database_path=database_path,
        workspace_root=state_root / "workspaces",
        allowed_roots=allowed_roots,
    )


load_dotenv()
app = application_from_environment()


def main() -> None:
    host = os.environ.get("SENTINELFORGE_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", os.environ.get("SENTINELFORGE_PORT", "8741")))
    uvicorn.run("sentinelforge.server:app", host=host, port=port, reload=False)

from pathlib import Path

from fastapi.testclient import TestClient

from sentinelforge.control import DetectionRunService, create_app
from sentinelforge.control.models import RunLifecycle, SecurityVerdict
from sentinelforge.control.service import RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore

REPOSITORY_ROOT = Path(__file__).parents[1]
FIXTURE = REPOSITORY_ROOT / "examples" / "vulnerable_shop"


def test_service_persists_candidate_and_patch_verdicts(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )

    queued = service.create(FIXTURE)
    completed = service.execute(queued.run_id)

    assert completed.lifecycle is RunLifecycle.COMPLETED
    assert completed.candidate_verdict is SecurityVerdict.BLOCKED
    assert completed.patch_verdict is SecurityVerdict.SAFE
    assert completed.result is not None
    events = store.list_events(queued.run_id)
    assert [event.kind for event in events] == [
        "run_queued",
        "scan_started",
        "scan_completed",
        "finding_confirmed",
        "isolated_patch_started",
        "patch_verified",
    ]
    assert [event.sequence for event in events] == sorted(event.sequence for event in events)


def test_service_rejects_repository_outside_allowlist(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(allowed,),
    )

    try:
        service.create(outside)
    except RepositoryNotAuthorizedError as error:
        assert "outside the configured allowed roots" in str(error)
    else:
        raise AssertionError("Repository outside allowlist was accepted")


def test_api_runs_detection_and_exposes_evidence_timeline(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )
    client = TestClient(app)

    response = client.post(
        "/api/runs",
        json={"repository": str(FIXTURE), "remediate": True},
    )

    assert response.status_code == 202
    run_id = response.json()["run_id"]
    run = client.get(f"/api/runs/{run_id}")
    events = client.get(f"/api/runs/{run_id}/events")
    assert run.status_code == 200
    assert run.json()["candidate_verdict"] == "blocked"
    assert run.json()["patch_verdict"] == "safe"
    assert events.status_code == 200
    assert events.json()[-1]["kind"] == "patch_verified"


def test_api_rejects_unapproved_repository(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(allowed,),
    )

    response = TestClient(app).post(
        "/api/runs",
        json={"repository": str(outside), "remediate": True},
    )

    assert response.status_code == 403


def test_dashboard_and_static_assets_are_served(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NVIDIA_API_KEY", "never-render-this-test-key")
    monkeypatch.setenv("NIM_MODEL", "nvidia/test-nemotron")
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )
    client = TestClient(app)

    dashboard = client.get("/")
    stylesheet = client.get("/assets/app.css")
    script = client.get("/assets/app.js")
    integrations = client.get("/api/integrations")

    assert dashboard.status_code == 200
    assert "The proof is the product" not in dashboard.text
    assert "Release security evidence" in dashboard.text
    assert "candidate-verdict" in dashboard.text
    assert stylesheet.status_code == 200
    assert "--blocked: #ff5a5f" in stylesheet.text
    assert script.status_code == 200
    assert "function renderRun" in script.text
    assert integrations.status_code == 200
    assert integrations.json()["nvidia_nim"] == {
        "status": "configured",
        "model": "nvidia/test-nemotron",
    }
    assert "never-render-this-test-key" not in integrations.text

from pathlib import Path

from fastapi.testclient import TestClient

from sentinelforge.control import DetectionRunService, create_app
from sentinelforge.control.models import (
    IntegrationHealth,
    PentestRunRequest,
    RunLifecycle,
    SecurityVerdict,
)
from sentinelforge.control.service import RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.inference import PatchProposal, ProposedFile
from sentinelforge.inference.openai_evidence import EvidenceDecision, EvidenceReview

REPOSITORY_ROOT = Path(__file__).parents[1]
FIXTURE = REPOSITORY_ROOT / "examples" / "vulnerable_shop"


class PassingPatchProposer:
    model = "nvidia/test-nemotron"

    def propose(self, finding, repository_root: str) -> PatchProposal:
        source_path = Path(repository_root) / finding.path
        source = source_path.read_text(encoding="utf-8")
        patched = source.replace(
            "    return order\n",
            "    if order.tenant_id != current_user.tenant_id:\n"
            '        raise HTTPException(status_code=404, detail="Not found")\n'
            "    return order\n",
        )
        regression = '''from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_model_patch_blocks_cross_tenant_access() -> None:
    response = client.get("/orders/1", headers={"x-user-id": "tenant-b-user"})
    assert response.status_code == 404
'''
        return PatchProposal(
            finding_id=finding.finding_id,
            provider="nvidia_nim",
            model=self.model,
            rationale="Add the missing tenant authorization guard.",
            files=[
                ProposedFile(path=finding.path, content=patched),
                ProposedFile(path="tests/test_security_model.py", content=regression),
            ],
            prompt_tokens=100,
            completion_tokens=80,
            latency_ms=250,
        )


class FailingPatchProposer:
    model = "nvidia/unavailable-model"

    def propose(self, finding, repository_root: str) -> PatchProposal:
        raise RuntimeError("simulated provider failure")


class PassingEvidenceReviewer:
    configured = True

    def review(self, *, run_id, candidate_verdict, evidence) -> EvidenceReview:
        assert run_id.startswith("sf_run_")
        assert candidate_verdict == "SAFE"
        assert evidence["verification"]["exit_code"] == 0
        assert evidence["human_gate"]["merge_or_deploy_allowed"] is False
        return EvidenceReview(
            decision=EvidenceDecision.APPROVE_FOR_HUMAN_REVIEW,
            risk_level="low",
            summary="The patch and regression evidence are internally consistent.",
            evidence_ids=evidence["evidence_hashes"],
            required_human_checks=["Review the authorization invariant."],
            model="gpt-5.6-sol",
            response_id="resp_test",
        )


class ExplodingEvidenceReviewer:
    configured = True

    def review(self, **kwargs):
        raise RuntimeError("unexpected provider failure with sensitive context")


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
        "candidate_selected",
        "patch_verified",
        "gpt_evidence_review_skipped",
    ]
    assert [event.sequence for event in events] == sorted(event.sequence for event in events)


def test_service_ranks_verified_model_and_deterministic_candidates(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
        patch_proposer=PassingPatchProposer(),
    )

    completed = service.execute(service.create(FIXTURE).run_id)

    assert completed.lifecycle is RunLifecycle.COMPLETED
    assert completed.patch_verdict is SecurityVerdict.SAFE
    assert completed.integration_health is IntegrationHealth.HEALTHY
    assert completed.result is not None
    assert len(completed.result["candidates"]) == 2
    assert all(candidate["verified"] for candidate in completed.result["candidates"])
    event_kinds = [event.kind for event in store.list_events(completed.run_id)]
    assert "model_candidate_started" in event_kinds
    assert "model_candidate_verified" in event_kinds
    assert "candidate_selected" in event_kinds


def test_release_proof_records_completed_gpt56_advisory_review(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
        evidence_reviewer=PassingEvidenceReviewer(),
    )

    completed = service.execute(service.create(FIXTURE).run_id)

    assert completed.patch_verdict is SecurityVerdict.SAFE
    assert completed.result is not None
    review = completed.result["openai_evidence_review"]
    assert review["status"] == "completed"
    assert review["decision"] == "approve_for_human_review"
    events = store.list_events(completed.run_id)
    assert events[-1].kind == "gpt_evidence_review_completed"
    assert events[-1].payload["advisory_only"] is True


def test_unexpected_gpt56_failure_cannot_fail_verified_release(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
        evidence_reviewer=ExplodingEvidenceReviewer(),
    )

    completed = service.execute(service.create(FIXTURE).run_id)

    assert completed.lifecycle is RunLifecycle.COMPLETED
    assert completed.patch_verdict is SecurityVerdict.SAFE
    assert completed.integration_health is IntegrationHealth.DEGRADED
    assert completed.result["openai_evidence_review"]["status"] == "failed"
    failure = store.list_events(completed.run_id)[-1]
    assert failure.kind == "gpt_evidence_review_failed"
    assert "sensitive context" not in str(failure.payload)


def test_service_keeps_security_verdict_when_model_provider_fails(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    service = DetectionRunService(
        store,
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
        patch_proposer=FailingPatchProposer(),
    )

    completed = service.execute(service.create(FIXTURE).run_id)

    assert completed.lifecycle is RunLifecycle.COMPLETED
    assert completed.patch_verdict is SecurityVerdict.SAFE
    assert completed.integration_health is IntegrationHealth.DEGRADED
    assert completed.result is not None
    assert len(completed.result["candidates"]) == 1
    events = store.list_events(completed.run_id)
    failure = next(event for event in events if event.kind == "model_candidate_failed")
    assert failure.payload["error_type"] == "RuntimeError"
    assert "simulated provider failure" not in str(failure.payload)


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
    assert events.json()[-1]["kind"] == "gpt_evidence_review_skipped"
    assert run.json()["result"]["selected_candidate_id"] == "deterministic-baseline"
    assert len(run.json()["result"]["candidates"]) == 1
    assert run.json()["result"]["openai_evidence_review"]["status"] == "skipped"


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
    monkeypatch.setenv("OPENAI_API_KEY", "never-render-openai-test-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6")
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
    nim_info = integrations.json()["nvidia_nim"]
    assert nim_info["status"] == "configured"
    assert nim_info["model"] == "nvidia/test-nemotron"
    # Enterprise enhancements: base_url present, vllm, openshell, etc
    assert "vllm" in integrations.json()
    assert "openshell" in integrations.json()
    assert "nemoclaw" in integrations.json()
    assert integrations.json()["openai_gpt56"]["status"] == "configured"
    assert integrations.json()["openai_gpt56"]["model"] == "gpt-5.6"
    assert "never-render-this-test-key" not in integrations.text
    assert "never-render-openai-test-key" not in integrations.text


def test_schedule_route_is_not_captured_as_a_run_id(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )

    response = TestClient(app).get("/api/pentest/schedule")

    assert response.status_code == 200
    assert response.json() == {"schedules": []}


def test_scheduler_lifespan_reports_active(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )

    with TestClient(app) as client:
        response = client.get("/api/integrations")

    assert response.json()["pentest_scheduler"]["status"] == "active"


def test_remote_schedule_admin_is_deny_by_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SENTINELFORGE_ADMIN_TOKEN", raising=False)
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )
    client = TestClient(app, client=("203.0.113.10", 50000))

    response = client.get("/api/pentest/schedule")

    assert response.status_code == 503


def test_public_run_endpoint_has_per_client_quota(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("NVIDIA_API_KEY", "")
    monkeypatch.setenv("NVIDIA_INFERENCE_API_KEY", "")
    monkeypatch.setenv("NVIDI_INFERENCE_API_KEY", "")
    app = create_app(
        database_path=tmp_path / "api.sqlite3",
        workspace_root=tmp_path / "workspaces",
        allowed_roots=(REPOSITORY_ROOT,),
    )
    client = TestClient(app, client=("203.0.113.20", 50000))

    responses = [
        client.post(
            "/api/runs",
            json={"repository": str(FIXTURE), "remediate": False},
        )
        for _ in range(4)
    ]

    assert [response.status_code for response in responses] == [202, 202, 202, 429]


def test_pentest_history_omits_large_result_payloads(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    request = PentestRunRequest(repository=str(FIXTURE))
    store.create_pentest_run("sf_pentest_history", request)
    store.update_pentest_run(
        "sf_pentest_history",
        results={"large_evidence": "x" * 1_000_000},
    )

    runs = store.list_pentest_runs(limit=20)

    assert len(runs) == 1
    assert runs[0].results is None

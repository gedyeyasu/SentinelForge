from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from sentinelforge.agents.dependencies import DependencyParser
from sentinelforge.agents.exploit_patterns import ExploitPatternScanner
from sentinelforge.agents.vuln_scanner import DependencyVulnerabilityScanner
from sentinelforge.cicd import CICDGenerator
from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import (
    CICDRequest,
    DetectionRunRequest,
    GitHubScanRequest,
    OwnershipRequest,
    OwnershipVerifyRequest,
    PentestMode,
    PentestRunRequest,
    PRRequest,
    RunEvent,
    RunRecord,
    ScanRequest,
)
from sentinelforge.control.service import DetectionRunService, RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.detectors import DjangoBOLADetector, FastAPIBOLADetector
from sentinelforge.integrations import RedHatAdvisory, RedHatSecurityDataClient
from sentinelforge.integrations.github import GitHubClient
from sentinelforge.ownership import OwnershipProver
from sentinelforge.pentest import PentestService
from sentinelforge.pentest_modes import list_modes
from sentinelforge.pr_generator import PRGenerator
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

    @app.get("/api/pentest/modes")
    def pentest_modes() -> list[dict[str, object]]:
        return list_modes()

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

    # --- GitHub Integration ---

    @app.get("/api/github/status")
    def github_status() -> dict[str, object]:
        client = GitHubClient()
        return client.health()

    @app.get("/api/github/repos")
    def github_list_repos(
        owner: str = Query(default=""),
        limit: int = Query(default=30, ge=1, le=100),
    ) -> dict[str, object]:
        client = GitHubClient()
        if not client.configured:
            raise HTTPException(
                status_code=400,
                detail="GITHUB_TOKEN not configured",
            )
        repos = client.list_repos(
            owner=owner or None,
            per_page=limit,
        )
        return {"repos": [r.to_dict() for r in repos], "total": len(repos)}

    # --- Source Code Scanning ---

    @app.post("/api/scan")
    def scan_repository(request: ScanRequest) -> dict[str, object]:
        repo_path = Path(request.repository).resolve()
        if not repo_path.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {repo_path}")

        findings = []
        findings.extend(FastAPIBOLADetector().scan(repo_path))
        findings.extend(DjangoBOLADetector().scan(repo_path))

        pattern_result = ExploitPatternScanner().scan_project(repo_path)

        dep_vulns = []
        try:
            parser = DependencyParser()
            manifest = parser.parse_project(repo_path)
            scanner = DependencyVulnerabilityScanner()
            scan_result = scanner.scan(manifest, repository_root=str(repo_path))
            dep_vulns = [v.to_dict() for v in scan_result.vulnerabilities]
        except Exception:
            pass

        return {
            "repository": str(repo_path),
            "bola_findings": [item.to_dict() for item in findings],
            "pattern_findings": pattern_result.to_dict(),
            "dependency_vulnerabilities": dep_vulns,
            "summary": {
                "bola_count": len(findings),
                "pattern_count": len(pattern_result.findings),
                "dep_vuln_count": len(dep_vulns),
                "total": len(findings) + len(pattern_result.findings) + len(dep_vulns),
            },
        }

    @app.post("/api/scan/github")
    def scan_github_repo(request: GitHubScanRequest) -> dict[str, object]:
        client = GitHubClient()
        if not client.configured:
            raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

        info = client.get_repo_info(request.owner, request.repo)
        if info is None:
            raise HTTPException(
                status_code=404,
                detail=f"Repo {request.owner}/{request.repo} not found",
            )
        clone_url = info.get("clone_url", "")

        try:
            repo_dir = client.clone_repo(
                clone_url,
                branch=request.branch or None,
            )
        except Exception as error:
            raise HTTPException(status_code=500, detail=f"Clone failed: {error}") from error

        findings = []
        findings.extend(FastAPIBOLADetector().scan(repo_dir))
        findings.extend(DjangoBOLADetector().scan(repo_dir))

        pattern_result = ExploitPatternScanner().scan(repo_dir)

        dep_vulns = []
        try:
            parser = DependencyParser()
            manifest = parser.parse_project(repo_dir)
            scanner = DependencyVulnerabilityScanner()
            scan_result = scanner.scan(manifest, repository_root=str(repo_dir))
            dep_vulns = [v.to_dict() for v in scan_result.vulnerabilities]
        except Exception:
            pass

        return {
            "repository": str(repo_dir),
            "github_repo": f"{request.owner}/{request.repo}",
            "bola_findings": [item.to_dict() for item in findings],
            "pattern_findings": pattern_result.to_dict(),
            "dependency_vulnerabilities": dep_vulns,
            "summary": {
                "bola_count": len(findings),
                "pattern_count": len(pattern_result.findings),
                "dep_vuln_count": len(dep_vulns),
                "total": len(findings) + len(pattern_result.findings) + len(dep_vulns),
            },
        }

    # --- PR Generation ---

    @app.post("/api/github/create-pr")
    def create_fix_pr(request: PRRequest) -> dict[str, object]:
        client = GitHubClient()
        if not client.configured:
            raise HTTPException(status_code=400, detail="GITHUB_TOKEN not configured")

        repo_dir = Path(request.repository)
        if not repo_dir.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {repo_dir}")

        pr_gen = PRGenerator()
        finding = request.finding
        branch_name = request.branch_name or pr_gen.generate_branch_name(finding)

        try:
            pr_gen.create_fix_branch(repo_dir, finding.get("finding_id", "fix"), branch_name)
        except Exception as error:
            raise HTTPException(
                status_code=500, detail=f"Branch creation failed: {error}"
            ) from error

        pr_body = pr_gen.generate_pr_body(finding)
        title = f"fix(security): {finding.get('title', 'Security vulnerability')}"

        try:
            pr_gen.push_branch(repo_dir, branch_name)
            pr = pr_gen.create_pull_request(
                repo_dir,
                title=title,
                body=pr_body,
                head=branch_name,
            )
        except Exception as error:
            raise HTTPException(status_code=500, detail=f"PR creation failed: {error}") from error

        if pr is None:
            return {"status": "failed", "error": "gh pr create failed"}

        return {
            "status": "created",
            "pr": pr.to_dict(),
        }

    # --- Ownership Proof ---

    @app.post("/api/ownership/challenge")
    def create_ownership_challenge(request: OwnershipRequest) -> dict[str, object]:
        prover = OwnershipProver()
        target = Path(request.target_path).resolve()
        if not target.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {target}")

        if request.challenge_type == "file":
            challenge = prover.create_file_challenge(target)
        elif request.challenge_type == "dns":
            challenge = prover.create_dns_challenge(request.target_path)
        elif request.challenge_type == "http":
            challenge = prover.create_http_challenge(request.target_path)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown challenge type: {request.challenge_type}",
            )
        return challenge.to_dict()

    @app.post("/api/ownership/verify")
    def verify_ownership(request: OwnershipVerifyRequest) -> dict[str, object]:
        prover = OwnershipProver()
        target = Path(request.target_path).resolve()

        if request.challenge_type == "file":
            verified = prover.verify_file_challenge(target, request.token)
        elif request.challenge_type == "dns":
            verified = prover.verify_dns_challenge(request.target_path, request.token)
        elif request.challenge_type == "http":
            verified = prover.verify_http_challenge(request.target_path, request.token)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown challenge type: {request.challenge_type}",
            )
        return {"verified": verified, "challenge_type": request.challenge_type}

    # --- CI/CD Generation ---

    @app.post("/api/cicd/generate")
    def generate_cicd(request: CICDRequest) -> dict[str, object]:
        repo_dir = Path(request.repository).resolve()
        if not repo_dir.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {repo_dir}")

        gen = CICDGenerator()
        if request.platform == "github_actions":
            workflow_file = gen.generate_github_actions(
                repo_dir,
                schedule_cron=request.schedule_cron,
                pentest_mode=request.pentest_mode,
            )
            return {
                "status": "generated",
                "platform": "github_actions",
                "file": str(workflow_file.relative_to(repo_dir)),
            }
        elif request.platform == "gitlab_ci":
            workflow_file = gen.generate_gitlab_ci(repo_dir)
            return {
                "status": "generated",
                "platform": "gitlab_ci",
                "file": str(workflow_file.relative_to(repo_dir)),
            }
        elif request.platform == "pre_commit":
            config_file = gen.generate_pre_commit_config(repo_dir)
            return {
                "status": "generated",
                "platform": "pre_commit",
                "file": str(config_file.relative_to(repo_dir)),
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown platform: {request.platform}",
            )

    return app

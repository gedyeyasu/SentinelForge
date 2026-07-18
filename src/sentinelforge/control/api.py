from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from sentinelforge.agents.dependencies import DependencyParser
from sentinelforge.agents.exploit_patterns import ExploitPatternScanner
from sentinelforge.agents.vuln_scanner import DependencyVulnerabilityScanner
from sentinelforge.cicd import CICDGenerator
from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import (
    CICDRequest,
    DetectionRunRequest,
    EnvironmentDetectRequest,
    GitHubScanRequest,
    OwnershipRequest,
    OwnershipVerifyRequest,
    PentestMode,
    PentestRunRequest,
    PRRequest,
    RunEvent,
    RunRecord,
    ScanRequest,
    VerifyCheckRequest,
    VerifyStartRequest,
)
from sentinelforge.control.service import DetectionRunService, RepositoryNotAuthorizedError
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.detectors import DjangoBOLADetector, FastAPIBOLADetector
from sentinelforge.environment import EnvironmentDetector
from sentinelforge.event_bus import EventBus, LiveEvent
from sentinelforge.integrations import RedHatAdvisory, RedHatSecurityDataClient
from sentinelforge.integrations.github import GitHubClient
from sentinelforge.ownership import OwnershipProver
from sentinelforge.pentest import PentestService
from sentinelforge.pentest_modes import list_modes
from sentinelforge.pr_generator import PRGenerator
from sentinelforge.scheduler import PentestScheduler
from sentinelforge.scope import ScopeValidationError, load_scope
from sentinelforge.verification import OwnershipVerificationService, VerificationMethod

logger = logging.getLogger(__name__)


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
        from sentinelforge.config import resolve_vllm_config
        from sentinelforge.integrations.openshell import get_policy

        nvidia = resolve_nvidia_config()
        vllm_cfg = resolve_vllm_config()
        # vLLM health quick check (no network call if not configured, just config)
        vllm_status = "awaiting_host"
        if os.environ.get("VLLM_BASE_URL"):
            try:
                import httpx as _httpx

                resp = _httpx.Client(timeout=2).get(f"{vllm_cfg.base_url}/models")
                vllm_status = "active" if resp.status_code == 200 else "awaiting_host"
            except Exception:
                vllm_status = "awaiting_host"

        # OpenShell policy existence
        try:
            pol = get_policy()
            openshell_status = "active" if pol else "configured"
            openshell_detail = {"policy": pol.name, "rules": len(pol.rules)}
        except Exception:
            openshell_status = "configured"
            openshell_detail = {}

        return {
            "deterministic": {"status": "active", "detectors": ["fastapi_bola", "django_bola"]},
            "nvidia_nim": {
                "status": "configured" if nvidia.configured else "awaiting_key",
                "model": nvidia.model,
                "base_url": nvidia.base_url,
            },
            "vllm": {
                "status": vllm_status,
                "model": vllm_cfg.model,
                "base_url": vllm_cfg.base_url,
            },
            "openshell": {"status": openshell_status, **openshell_detail},
            "red_hat_security_data": {"status": "public_api", "feeds": ["csaf", "oval"]},
            "hiddenlayer": {
                "status": (
                    "configured" if os.environ.get("HIDDENLAYER_API_KEY") else "local_fallback"
                ),
                "mode": "api" if os.environ.get("HIDDENLAYER_API_KEY") else "local_pattern",
            },
            "github": {
                "status": "configured" if os.environ.get("GITHUB_TOKEN") else "awaiting_key",
            },
            "pentest_scheduler": {"status": "active"},
            "brev": {"status": "manifest_exists", "doc": "docs/BREV.md"},
            "nemoclaw": {
                "status": "active" if Path("config/agents.yaml").is_file() else "missing",
                "roster": "config/agents.yaml",
                "heartbeat": "HEARTBEAT.md",
            },
        }

    @app.get("/api/agents")
    def list_agents() -> dict[str, object]:
        agents_path = Path("config/agents.yaml")
        if not agents_path.is_file():
            # fallback lookups
            fallback = Path(__file__).parents[2] / "config" / "agents.yaml"
            for p in [fallback, Path("config/agents.yaml")]:
                if p.is_file():
                    agents_path = p
                    break
        if not agents_path.is_file():
            return {"status": "missing", "agents": [], "message": "config/agents.yaml not found"}
        try:
            import yaml

            data = yaml.safe_load(agents_path.read_text(encoding="utf-8"))
            return {
                "status": "active",
                "file": str(agents_path),
                "schema_version": data.get("schema_version", "0.1"),
                "orchestrator": data.get("orchestrator", "nemoclaw"),
                "agents": data.get("agents", {}),
                "routing": data.get("routing", {}),
                "spawn_depth_limit": data.get("spawn_depth_limit", 2),
                "telemetry": data.get("telemetry", {}),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc), "file": str(agents_path)}

    @app.get("/api/pentest/{run_id}/traces")
    def list_pentest_traces(run_id: str) -> dict[str, object]:
        pentest = service.store.get_pentest_run(run_id)
        if pentest is None:
            # also check runs table
            if service.store.get_run(run_id) is None:
                raise HTTPException(status_code=404, detail="Run not found")
        traces = service.store.list_agent_traces(run_id)
        total_input = sum(t.get("input_tokens") or 0 for t in traces)
        total_output = sum(t.get("output_tokens") or 0 for t in traces)
        total_cost = sum(t.get("cost_usd") or 0 for t in traces)
        return {
            "run_id": run_id,
            "traces": traces,
            "summary": {
                "total_traces": len(traces),
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
                "agents_involved": list({t.get("agent_role") for t in traces}),
            },
        }

    @app.get("/api/learning/invariants")
    def list_invariants(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, object]:
        inv = service.store.list_security_invariants(limit=limit)
        return {"invariants": inv, "total": len(inv)}

    @app.get("/api/learning/memory/{target_id}")
    def get_memory(target_id: str) -> dict[str, object]:
        mem = service.store.get_target_memory(target_id)
        if mem is None:
            raise HTTPException(status_code=404, detail="Target memory not found")
        return {"target_id": target_id, "memory": mem}

    @app.get("/api/heartbeat")
    def get_heartbeat() -> dict[str, object]:
        hb_path = Path("HEARTBEAT.md")
        agents_path = Path("config/agents.yaml")
        return {
            "heartbeat_exists": hb_path.is_file(),
            "agents_exists": agents_path.is_file(),
            "last_modified": (
                hb_path.stat().st_mtime if hb_path.is_file() else None
            ),
            "content_preview": (
                hb_path.read_text(encoding="utf-8")[:2000]
                if hb_path.is_file() else None
            ),
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
            run_id = pentest_service.create_and_start(request, scope=scope)
        except Exception as error:
            raise HTTPException(status_code=500, detail=str(error)) from error
        return {"run_id": run_id, "status": "started"}

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

    @app.get("/api/pentest/{run_id}/stream")
    async def stream_pentest_events(run_id: str):
        from sentinelforge.event_bus import EventBus

        if service.store.get_pentest_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Pentest run not found")

        bus = EventBus.instance()
        queue = bus.subscribe(run_id)

        async def event_generator():
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    except TimeoutError:
                        yield f": keepalive {time.time()}\n\n"
                        continue
                    if event is None:
                        break
                    data = json.dumps({
                        "phase": event.phase,
                        "kind": event.kind,
                        "timestamp": event.timestamp,
                        "payload": event.payload,
                    })
                    yield f"data: {data}\n\n"
                    if event.kind == "run_completed":
                        break
            finally:
                bus.unsubscribe(run_id, queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

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

    # --- GitHub Integration (Token + OAuth) ---

    @app.get("/api/github/status")
    def github_status() -> dict[str, object]:
        # Try OAuth manager first for richer status
        try:
            from sentinelforge.integrations.github_oauth import GitHubOAuthManager

            oauth_mgr = GitHubOAuthManager()
            oauth_status = oauth_mgr.get_status()
            if oauth_status.get("has_token"):
                # Validate via GitHub API
                client = GitHubClient()
                health = client.health()
                health["source"] = oauth_status.get("source", "oauth")
                health["oauth"] = oauth_mgr.get_oauth_config_status()
                health["login"] = health.get("login") or oauth_status.get("login")
                return health
        except Exception:
            pass

        client = GitHubClient()
        status = client.health()
        try:
            from sentinelforge.integrations.github_oauth import GitHubOAuthManager

            oauth_mgr = GitHubOAuthManager()
            status["oauth"] = oauth_mgr.get_oauth_config_status()
        except Exception:
            pass
        return status

    @app.get("/api/github/oauth/config")
    def github_oauth_config() -> dict[str, object]:
        from sentinelforge.integrations.github_oauth import GitHubOAuthManager

        mgr = GitHubOAuthManager()
        return mgr.get_oauth_config_status()

    @app.get("/api/github/oauth/start")
    def github_oauth_start(
        redirect_after: str = Query(default="/", description="Where to redirect after auth"),
    ) -> dict[str, object]:
        from sentinelforge.integrations.github_oauth import GitHubOAuthManager

        mgr = GitHubOAuthManager()
        if not mgr.config.configured:
            raise HTTPException(
                status_code=400,
                detail="GitHub OAuth not configured: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env. See docs/GITHUB_OAUTH.md",
            )
        try:
            authorize_url, state = mgr.create_authorize_url(redirect_after=redirect_after)
            return {
                "authorize_url": authorize_url,
                "state": state,
                "message": "Redirect user to authorize_url",
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    @app.get("/api/github/oauth/callback")
    def github_oauth_callback(
        code: str = Query(default=""),
        state: str = Query(default=""),
    ):
        from fastapi.responses import HTMLResponse

        from sentinelforge.integrations.github_oauth import GitHubOAuthManager

        mgr = GitHubOAuthManager()

        # Handle error from GitHub
        html_error = """
        <html><body style="font-family:sans-serif; padding:2rem">
        <h2>GitHub OAuth Failed</h2><p>{error}</p>
        <p><a href="/">Back to SentinelForge</a></p>
        </body></html>
        """

        try:
            if not code:
                return HTMLResponse(content=html_error.format(error="No code provided from GitHub"), status_code=400)

            token = mgr.exchange_code_for_token(code, state)

            html_success = f"""
            <html><head><title>GitHub Connected</title></head>
            <body style="font-family:Instrument Sans, sans-serif; background:#0E1417; color:#F1F4F2; padding:2rem; text-align:center">
            <div style="max-width:480px; margin:4rem auto; background:#151D21; border:1px solid #29353A; border-radius:6px; padding:2rem">
            <h2 style="color:#34D399">✓ GitHub Connected</h2>
            <p>Authenticated as <strong>{token.login or 'GitHub User'}</strong></p>
            <p style="color:#91A09B; font-size:14px">Token stored securely in .sentinelforge/github_token.json with 600 permissions. You can close this window.</p>
            <p style="margin-top:1.5rem"><a href="/" style="color:#55B6FF; text-decoration:none">→ Back to SentinelForge Dashboard</a></p>
            <script>
              // Notify opener window if in popup
              if (window.opener) {{
                window.opener.postMessage({{"type":"github_oauth_success","login":"{token.login or ''}"}}, "*");
                setTimeout(() => window.close(), 2000);
              }}
            </script>
            </div>
            </body></html>
            """
            return HTMLResponse(content=html_success)

        except ValueError as e:
            return HTMLResponse(content=html_error.format(error=str(e)), status_code=400)
        except Exception as e:
            return HTMLResponse(content=html_error.format(error=f"OAuth exchange failed: {e}"), status_code=500)

    @app.post("/api/github/oauth/disconnect")
    def github_oauth_disconnect() -> dict[str, object]:
        from sentinelforge.integrations.github_oauth import GitHubOAuthManager

        mgr = GitHubOAuthManager()
        deleted = mgr.delete_token()
        return {"status": "disconnected" if deleted else "no_token", "deleted": deleted}

    @app.get("/api/github/repos")
    def github_list_repos(
        owner: str = Query(default=""),
        limit: int = Query(default=30, ge=1, le=100),
        search: str = Query(default="", description="Filter repos by name"),
        sort: str = Query(default="updated", description="Sort by updated, created, pushed, full_name"),
    ) -> dict[str, object]:
        client = GitHubClient()
        if not client.configured:
            raise HTTPException(
                status_code=400,
                detail="GITHUB_TOKEN not configured. Connect via OAuth at /api/github/oauth/start or set GITHUB_TOKEN in .env",
            )
        repos = client.list_repos(
            owner=owner or None,
            per_page=limit,
        )
        # Filter by search if provided
        if search:
            search_lower = search.lower()
            repos = [r for r in repos if search_lower in r.name.lower() or search_lower in r.full_name.lower()]

        # Sort
        if sort == "updated":
            repos = sorted(repos, key=lambda r: r.updated_at, reverse=True)
        elif sort == "full_name":
            repos = sorted(repos, key=lambda r: r.full_name.lower())

        return {
            "repos": [r.to_dict() for r in repos],
            "total": len(repos),
            "filters": {"owner": owner, "search": search, "sort": sort, "limit": limit},
        }

    # --- Source Code Scanning ---

    def _run_scan_background(
        scan_id: str, repo_path: Path, bus
    ) -> None:
        """Run the full scan pipeline, emitting live events."""
        def emit(phase, kind, payload):
            bus.publish(LiveEvent(
                run_id=scan_id, phase=phase, kind=kind,
                timestamp=time.time(), payload=payload,
            ))

        emit("scan", "scan_started", {
            "repository": str(repo_path),
            "message": f"Starting security scan of {repo_path.name}",
        })

        findings = []

        # Phase 1: BOLA Detection
        emit("fastapi_bola", "agent_started", {
            "agent": "FastAPIBOLADetector",
            "message": "Scanning for FastAPI BOLA vulnerabilities",
        })
        try:
            fastapi_findings = FastAPIBOLADetector().scan(repo_path)
            findings.extend(fastapi_findings)
            emit("fastapi_bola", "agent_completed", {
                "agent": "FastAPIBOLADetector",
                "message": f"FastAPI scan: {len(fastapi_findings)} findings in {repo_path.name}",
                "finding_count": len(fastapi_findings),
            })
        except Exception as e:
            emit("fastapi_bola", "agent_error", {
                "agent": "FastAPIBOLADetector",
                "message": f"FastAPI scan error: {e}",
            })

        emit("django_bola", "agent_started", {
            "agent": "DjangoBOLADetector",
            "message": "Scanning for Django BOLA vulnerabilities",
        })
        try:
            django_findings = DjangoBOLADetector().scan(repo_path)
            findings.extend(django_findings)
            emit("django_bola", "agent_completed", {
                "agent": "DjangoBOLADetector",
                "message": f"Django scan: {len(django_findings)} findings",
                "finding_count": len(django_findings),
            })
        except Exception as e:
            emit("django_bola", "agent_error", {
                "agent": "DjangoBOLADetector",
                "message": f"Django scan error: {e}",
            })

        # Phase 2: Exploit Pattern Scan
        emit("pattern_scan", "agent_started", {
            "agent": "ExploitPatternScanner",
            "message": "Scanning for code-level exploit patterns",
        })

        def pattern_progress(kind, payload):
            if kind == "started":
                msg = (
                    f"Scanning {payload['total_files']} files "
                    f"with {payload['patterns_per_file']} patterns"
                )
            elif kind == "finding":
                msg = payload.get("description", "")
            elif kind == "checking_file":
                msg = f"Scanning {payload['file']}"
            elif kind == "file_clean":
                msg = (
                    f"{payload['file']} clean "
                    f"({payload['patterns_checked']} patterns)"
                )
            elif kind == "completed":
                msg = (
                    f"Pattern scan: {payload['finding_count']} findings "
                    f"in {payload['files_scanned']} files "
                    f"({payload['duration_ms']}ms)"
                )
            else:
                msg = str(payload)
            emit("pattern_scan", kind, {
                "agent": "ExploitPatternScanner",
                "message": msg,
                **payload,
            })

        pattern_result = ExploitPatternScanner().scan_project(
            repo_path, progress_callback=pattern_progress
        )

        # Phase 3: Dependency Analysis
        dep_vulns = []
        dep_warnings = []

        emit("dependency_parse", "agent_started", {
            "agent": "DependencyParser",
            "message": "Parsing dependency manifests",
        })
        try:
            parser = DependencyParser()
            manifest = parser.parse_project(repo_path)
            dep_count = len(manifest.all_dependencies)
            emit("dependency_parse", "agent_completed", {
                "agent": "DependencyParser",
                "message": f"Parsed {dep_count} dependencies from manifest files",
                "dependency_count": dep_count,
            })

            emit("vuln_scan", "agent_started", {
                "agent": "DependencyVulnerabilityScanner",
                "message": "Cross-referencing dependencies with Red Hat advisories",
            })

            def vuln_progress(kind, payload):
                if kind == "started":
                    msg = (
                        f"Checking {payload['unique_packages']} packages "
                        f"against Red Hat advisories"
                    )
                elif kind == "checking_package":
                    msg = (
                        f"Checking {payload['package']} "
                        f"{payload.get('version', '')}"
                    )
                elif kind == "vuln_found":
                    msg = (
                        f"Advisory {payload['advisory_id']}: "
                        f"{payload['severity']} in {payload['package']}"
                    )
                elif kind == "package_complete":
                    msg = (
                        f"{payload['package']} complete: "
                        f"{payload['advisories_checked']} advisories, "
                        f"{payload['vulnerabilities']} vulns"
                    )
                elif kind == "completed":
                    msg = (
                        f"Dependency scan: "
                        f"{payload['vulnerability_count']} vulns "
                        f"in {payload['unique_packages']} packages"
                    )
                else:
                    msg = str(payload)
                emit("vuln_scan", kind, {
                    "agent": "DependencyVulnerabilityScanner",
                    "message": msg,
                    **payload,
                })

            scanner = DependencyVulnerabilityScanner()
            scan_result = scanner.scan(
                manifest, repository_root=str(repo_path),
                progress_callback=vuln_progress,
            )
            dep_vulns = [v.to_dict() for v in scan_result.vulnerabilities]
        except Exception as error:
            dep_warnings.append(f"Dependency scan skipped: {error}")
            emit("vuln_scan", "agent_error", {
                "agent": "DependencyVulnerabilityScanner",
                "message": f"Dependency scan error: {error}",
            })

        # Final results
        result = {
            "repository": str(repo_path),
            "bola_findings": [item.to_dict() for item in findings],
            "pattern_findings": pattern_result.to_dict(),
            "dependency_vulnerabilities": dep_vulns,
            "warnings": dep_warnings,
            "summary": {
                "bola_count": len(findings),
                "pattern_count": len(pattern_result.findings),
                "dep_vuln_count": len(dep_vulns),
                "total": len(findings) + len(pattern_result.findings) + len(dep_vulns),
            },
        }
        emit("scan", "scan_completed", {
            "result": result,
            "message": f"Scan complete: {result['summary']['total']} findings",
        })

    @app.post("/api/scan")
    def scan_repository(request: ScanRequest) -> dict[str, object]:
        repo_path = Path(request.repository).resolve()
        if not repo_path.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {repo_path}")

        scan_id = "sf_scan_" + uuid.uuid4().hex[:12]
        bus = EventBus.instance()

        thread = threading.Thread(
            target=_run_scan_background,
            args=(scan_id, repo_path, bus),
            name=f"scan-{scan_id}",
            daemon=True,
        )
        thread.start()
        return {"scan_id": scan_id, "status": "started"}

    @app.get("/api/scan/{scan_id}/stream")
    async def stream_scan_events(scan_id: str):
        bus = EventBus.instance()
        queue = bus.subscribe(scan_id)

        async def event_generator():
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    except TimeoutError:
                        yield f": keepalive {time.time()}\n\n"
                        continue
                    if event is None:
                        break
                    data = json.dumps({
                        "phase": event.phase,
                        "kind": event.kind,
                        "timestamp": event.timestamp,
                        "payload": event.payload,
                    })
                    yield f"data: {data}\n\n"
                    if event.kind == "scan_completed":
                        break
            finally:
                bus.unsubscribe(scan_id, queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/scan/{scan_id}")
    def get_scan_result(scan_id: str) -> dict[str, object]:
        bus = EventBus.instance()
        log = bus.get_log(scan_id)
        for event in reversed(log):
            if event.kind == "scan_completed":
                return event.payload.get("result", {})
        raise HTTPException(status_code=404, detail="Scan not found or still running")

    @app.post("/api/scan/github")
    def scan_github_repo(request: GitHubScanRequest) -> dict[str, object]:
        client = GitHubClient()
        if not client.configured:
            raise HTTPException(
                status_code=400, detail="GITHUB_TOKEN not configured"
            )

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
            raise HTTPException(
                status_code=500, detail=f"Clone failed: {error}"
            ) from error

        scan_id = "sf_scan_" + uuid.uuid4().hex[:12]
        bus = EventBus.instance()

        thread = threading.Thread(
            target=_run_scan_background,
            args=(scan_id, repo_dir, bus),
            name=f"scan-{scan_id}",
            daemon=True,
        )
        thread.start()
        return {
            "scan_id": scan_id,
            "status": "started",
            "github_repo": f"{request.owner}/{request.repo}",
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

    # --- Enterprise Ownership Verification ---

    _verification_service = OwnershipVerificationService()

    @app.post("/api/verify/start")
    def verify_start(request: VerifyStartRequest) -> dict[str, object]:
        try:
            method = VerificationMethod(request.method)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown method: {request.method}. "
                f"Valid: {', '.join(m.value for m in VerificationMethod)}",
            ) from None

        challenge = _verification_service.start_verification(
            request.target, method
        )
        return {
            "challenge_id": challenge.challenge_id,
            "method": challenge.method.value,
            "target": challenge.target,
            "metadata": challenge.metadata,
            "expires_at": challenge.expires_at,
        }

    @app.post("/api/verify/check")
    def verify_check(request: VerifyCheckRequest) -> dict[str, object]:
        result = _verification_service.check_verification(request.challenge_id)
        return result.to_dict()

    @app.get("/api/verify/status")
    def verify_status(target: str = Query(min_length=1)) -> dict[str, object]:
        verified = _verification_service.is_target_verified(target)
        challenges = _verification_service.list_challenges(target)
        return {
            "target": target,
            "verified": verified,
            "challenges": [c.to_dict() for c in challenges],
        }

    # --- Environment Detection ---

    @app.post("/api/environment/detect")
    def detect_environment(request: EnvironmentDetectRequest) -> dict[str, object]:
        detector = EnvironmentDetector()
        classification = detector.detect(request.url)
        return classification.to_dict()

    @app.get("/api/environment/scan")
    def scan_environment_hints(
        repository: str = Query(min_length=1),
    ) -> dict[str, object]:
        repo_path = Path(repository).resolve()
        if not repo_path.is_dir():
            raise HTTPException(status_code=400, detail=f"Not a directory: {repo_path}")
        detector = EnvironmentDetector()
        hints = detector.scan_codebase_for_env_hints(str(repo_path))
        return hints

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

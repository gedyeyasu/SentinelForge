from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from dotenv import load_dotenv

from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import PentestRunRequest
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.inference import NIMPatchProposer
from sentinelforge.pentest import PentestService
from sentinelforge.remediation import (
    CandidateEvaluation,
    FastAPIBOLAPatcher,
    count_changed_lines,
    materialize_proposal,
    rank_candidates,
)
from sentinelforge.scope import ScopeValidationError, load_scope
from sentinelforge.verification import verify_python_project


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def scan_command(args: argparse.Namespace) -> int:
    root = Path(args.repository)
    findings = FastAPIBOLADetector().scan(root)
    payload = {"repository": str(root.resolve()), "findings": [item.to_dict() for item in findings]}
    if args.output:
        _write_json(Path(args.output), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if findings and args.fail_on_finding else 0


def remediate_command(args: argparse.Namespace) -> int:
    root = Path(args.repository)
    findings = FastAPIBOLADetector().scan(root)
    if not findings:
        print(json.dumps({"status": "no_findings", "repository": str(root.resolve())}, indent=2))
        return 0
    finding = findings[0]
    run_root = Path(args.run_root) / finding.finding_id
    bundle = FastAPIBOLAPatcher().create_bundle(finding, root, run_root)
    report = verify_python_project(bundle.patched_root, timeout_seconds=args.timeout)
    payload = {
        "status": "verified" if report.exit_code == 0 else "verification_failed",
        "finding": finding.to_dict(),
        "patch_bundle": bundle.to_dict(),
        "verification": report.to_dict(),
    }
    _write_json(run_root / "result.json", payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return report.exit_code


def nim_health_command(args: argparse.Namespace) -> int:
    proposer = _nim_proposer(args)
    health = proposer.health()
    print(json.dumps(health, indent=2, sort_keys=True))
    return 0 if health["available"] else 1


def nim_remediate_command(args: argparse.Namespace) -> int:
    root = Path(args.repository)
    findings = FastAPIBOLADetector().scan(root)
    if not findings:
        print(json.dumps({"status": "no_findings", "repository": str(root.resolve())}, indent=2))
        return 0
    finding = findings[0]
    run_id = "sf_nim_" + uuid.uuid4().hex[:12]
    run_root = Path(args.run_root) / run_id
    proposer = _nim_proposer(args)
    proposal = proposer.propose(finding, str(root))

    deterministic = FastAPIBOLAPatcher().create_bundle(finding, root, run_root / "deterministic")
    model_bundle = materialize_proposal(proposal, finding, root, run_root / "nvidia_nim")
    deterministic_report = verify_python_project(deterministic.patched_root, args.timeout)
    model_report = verify_python_project(model_bundle.patched_root, args.timeout)
    ranked = rank_candidates(
        [
            CandidateEvaluation(
                "deterministic-baseline",
                "deterministic",
                deterministic,
                deterministic_report,
                count_changed_lines(deterministic.patch_file),
            ),
            CandidateEvaluation(
                "nemotron-proposal",
                "nvidia_nim",
                model_bundle,
                model_report,
                count_changed_lines(model_bundle.patch_file),
            ),
        ]
    )
    payload = {
        "run_id": run_id,
        "finding": finding.to_dict(),
        "proposal": {
            "finding_id": proposal.finding_id,
            "provider": proposal.provider,
            "model": proposal.model,
            "rationale": proposal.rationale,
            "changed_paths": [item.path for item in proposal.files],
            "prompt_tokens": proposal.prompt_tokens,
            "completion_tokens": proposal.completion_tokens,
            "latency_ms": proposal.latency_ms,
        },
        "ranking": [
            {
                "candidate_id": item.candidate_id,
                "source": item.source,
                "verified": item.verification.exit_code == 0,
                "changed_lines": item.changed_lines,
                "patch_sha256": item.bundle.patch_sha256,
            }
            for item in ranked
        ],
        "selected": ranked[0].candidate_id if ranked[0].verification.exit_code == 0 else None,
    }
    _write_json(run_root / "result.json", payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["selected"] is not None else 1


def _nim_proposer(args: argparse.Namespace) -> NIMPatchProposer:
    config = resolve_nvidia_config()
    if not config.configured:
        raise SystemExit(
            "NVIDIA_API_KEY (or NVIDIA_INFERENCE_API_KEY) is required; "
            "it is never stored or printed"
        )
    return NIMPatchProposer(
        api_key=config.api_key,
        model=args.model,
        base_url=args.base_url,
        timeout_seconds=args.timeout,
    )


def pentest_command(args: argparse.Namespace) -> int:
    scope_path = Path(args.scope)
    if not scope_path.is_file():
        print(json.dumps({"error": f"Scope file not found: {scope_path}"}, indent=2))
        return 1
    try:
        scope = load_scope(scope_path)
    except ScopeValidationError as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 1

    store = SQLiteRunStore(Path(args.db))
    pentest_service = PentestService(store)

    from sentinelforge.control.models import PentestMode as PM

    request = PentestRunRequest(
        repository=args.repository,
        scope_file=str(scope_path),
        attack_only_source=args.source_only,
        mode=PM(args.mode),
    )
    try:
        result = pentest_service.create_and_execute(request, scope=scope)
    except Exception as error:
        print(json.dumps({"error": str(error)}, indent=2))
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    has_success = any(
        r.get("outcome") == "success"
        for r in result.get("pentest_run", {}).get("results", {}).get("receipts", [])
        if isinstance(r, dict)
    )
    return 1 if has_success else 0


def pentest_list_command(args: argparse.Namespace) -> int:
    store = SQLiteRunStore(Path(args.db))
    runs = store.list_pentest_runs(limit=args.limit, offset=args.offset)
    payload = {
        "runs": [r.model_dump() for r in runs],
        "total": len(runs),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def pentest_schedule_command(args: argparse.Namespace) -> int:
    from sentinelforge.scheduler import PentestScheduler

    store = SQLiteRunStore(Path(args.db))
    sched = PentestScheduler(store)

    if args.action == "create":
        schedule = sched.create_schedule(
            repository=args.repository,
            scope_file=args.scope,
            mode=args.mode,
            interval_minutes=args.interval,
        )
        print(json.dumps(schedule.to_dict(), indent=2, sort_keys=True))
        return 0
    elif args.action == "list":
        schedules = sched.list_schedules()
        payload = {"schedules": [s.to_dict() for s in schedules]}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    elif args.action == "delete":
        deleted = sched.delete_schedule(args.schedule_id)
        if deleted:
            print(json.dumps({"status": "deleted", "schedule_id": args.schedule_id}))
            return 0
        print(json.dumps({"error": "Schedule not found"}))
        return 1
    return 1


def build_parser() -> argparse.ArgumentParser:
    nvidia = resolve_nvidia_config()
    parser = argparse.ArgumentParser(prog="sentinelforge")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Detect supported security defects")
    scan.add_argument("repository")
    scan.add_argument("--output")
    scan.add_argument("--fail-on-finding", action="store_true")
    scan.set_defaults(handler=scan_command)

    remediate = subparsers.add_parser(
        "remediate", help="Detect, patch in an isolated workspace, and verify"
    )
    remediate.add_argument("repository")
    remediate.add_argument("--run-root", default=".sentinelforge/runs")
    remediate.add_argument("--timeout", type=int, default=90)
    remediate.set_defaults(handler=remediate_command)

    nim_health = subparsers.add_parser("nim-health", help="Check the configured NVIDIA model")
    nim_health.add_argument(
        "--base-url",
        default=nvidia.base_url,
    )
    nim_health.add_argument(
        "--model",
        default=nvidia.model,
    )
    nim_health.add_argument("--timeout", type=int, default=30)
    nim_health.set_defaults(handler=nim_health_command)

    nim_remediate = subparsers.add_parser(
        "nim-remediate",
        help="Compare a Nemotron patch proposal with the deterministic verified baseline",
    )
    nim_remediate.add_argument("repository")
    nim_remediate.add_argument("--run-root", default=".sentinelforge/nim-runs")
    nim_remediate.add_argument(
        "--base-url",
        default=nvidia.base_url,
    )
    nim_remediate.add_argument(
        "--model",
        default=nvidia.model,
    )
    nim_remediate.add_argument("--timeout", type=int, default=90)
    nim_remediate.set_defaults(handler=nim_remediate_command)

    pentest = subparsers.add_parser(
        "pentest", help="Run active pentesting against an authorized staging target"
    )
    pentest.add_argument("repository")
    pentest.add_argument(
        "--scope", default="config/scope.yaml", help="Path to scope.yaml"
    )
    pentest.add_argument(
        "--db", default=".sentinelforge/control/runs.sqlite3", help="SQLite database path"
    )
    pentest.add_argument(
        "--source-only",
        action="store_true",
        help="Discover routes from source only, do not probe a live target",
    )
    pentest.add_argument(
        "--mode",
        default="standard",
        choices=["quick", "standard", "full", "targeted", "pre_release", "continuous"],
        help="Pentest mode (default: standard)",
    )
    pentest.set_defaults(handler=pentest_command)

    pentest_list = subparsers.add_parser(
        "pentest-list", help="List recent pentest runs"
    )
    pentest_list.add_argument(
        "--db", default=".sentinelforge/control/runs.sqlite3"
    )
    pentest_list.add_argument("--limit", type=int, default=20)
    pentest_list.add_argument("--offset", type=int, default=0)
    pentest_list.set_defaults(handler=pentest_list_command)

    pentest_sched = subparsers.add_parser(
        "pentest-schedule", help="Manage pentest schedules"
    )
    pentest_sched.add_argument(
        "action", choices=["create", "list", "delete"]
    )
    pentest_sched.add_argument("--repository", default="")
    pentest_sched.add_argument("--scope", default="config/scope.yaml")
    pentest_sched.add_argument(
        "--mode", default="standard",
        choices=["quick", "standard", "full", "targeted", "pre_release", "continuous"],
    )
    pentest_sched.add_argument(
        "--interval", type=int, default=60,
        help="Interval in minutes between scheduled runs",
    )
    pentest_sched.add_argument("--schedule-id", default="")
    pentest_sched.add_argument(
        "--db", default=".sentinelforge/control/runs.sqlite3"
    )
    pentest_sched.set_defaults(handler=pentest_schedule_command)

    return parser


def main() -> int:
    load_dotenv()
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())

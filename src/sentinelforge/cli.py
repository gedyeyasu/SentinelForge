from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from dotenv import load_dotenv

from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.inference import NIMPatchProposer
from sentinelforge.remediation import (
    CandidateEvaluation,
    FastAPIBOLAPatcher,
    count_changed_lines,
    materialize_proposal,
    rank_candidates,
)
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
    api_key = os.environ.get("NVIDIA_API_KEY", "")
    if not api_key:
        raise SystemExit("NVIDIA_API_KEY is required; it is never stored or printed")
    return NIMPatchProposer(
        api_key=api_key,
        model=args.model,
        base_url=args.base_url,
        timeout_seconds=args.timeout,
    )


def build_parser() -> argparse.ArgumentParser:
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
        default=os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
    )
    nim_health.add_argument(
        "--model",
        default=os.environ.get("NIM_MODEL", "nvidia/nemotron-3-super-120b-a12b"),
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
        default=os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
    )
    nim_remediate.add_argument(
        "--model",
        default=os.environ.get("NIM_MODEL", "nvidia/nemotron-3-super-120b-a12b"),
    )
    nim_remediate.add_argument("--timeout", type=int, default=90)
    nim_remediate.set_defaults(handler=nim_remediate_command)
    return parser


def main() -> int:
    load_dotenv()
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())

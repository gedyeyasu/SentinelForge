from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.remediation import FastAPIBOLAPatcher
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
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())

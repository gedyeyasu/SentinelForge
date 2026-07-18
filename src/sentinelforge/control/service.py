from __future__ import annotations

import uuid
from pathlib import Path

from sentinelforge.control.models import RunLifecycle, RunRecord, SecurityVerdict
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.remediation import FastAPIBOLAPatcher
from sentinelforge.verification import verify_python_project


class RepositoryNotAuthorizedError(ValueError):
    pass


class DetectionRunService:
    def __init__(
        self,
        store: SQLiteRunStore,
        workspace_root: Path,
        allowed_roots: tuple[Path, ...],
    ) -> None:
        self.store = store
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.allowed_roots = tuple(root.resolve() for root in allowed_roots)
        if not self.allowed_roots:
            raise ValueError("At least one allowed repository root is required")

    def create(self, repository: Path) -> RunRecord:
        resolved = self._authorized_repository(repository)
        run_id = "sf_run_" + uuid.uuid4().hex[:12]
        record = self.store.create_run(run_id, resolved)
        self.store.append_event(
            run_id,
            phase="preflight",
            kind="run_queued",
            payload={"repository": str(resolved)},
        )
        return record

    def execute(self, run_id: str, remediate: bool = True) -> RunRecord:
        record = self.store.get_run(run_id)
        if record is None:
            raise KeyError(run_id)
        repository = self._authorized_repository(Path(record.repository))
        self.store.update_run(run_id, lifecycle=RunLifecycle.RUNNING)
        self.store.append_event(
            run_id,
            phase="detection",
            kind="scan_started",
            payload={"detector": FastAPIBOLADetector.rule_id},
        )
        try:
            findings = FastAPIBOLADetector().scan(repository)
            self.store.append_event(
                run_id,
                phase="detection",
                kind="scan_completed",
                payload={"finding_count": len(findings)},
            )
            if not findings:
                return self.store.update_run(
                    run_id,
                    lifecycle=RunLifecycle.COMPLETED,
                    candidate_verdict=SecurityVerdict.SAFE,
                    patch_verdict=SecurityVerdict.NOT_APPLICABLE,
                    result={"findings": []},
                )

            finding = findings[0]
            self.store.update_run(run_id, candidate_verdict=SecurityVerdict.BLOCKED)
            self.store.append_event(
                run_id,
                phase="detection",
                kind="finding_confirmed",
                payload={
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "invariant": finding.invariant,
                },
            )
            if not remediate:
                return self.store.update_run(
                    run_id,
                    lifecycle=RunLifecycle.COMPLETED,
                    patch_verdict=SecurityVerdict.NOT_APPLICABLE,
                    result={"findings": [finding.to_dict()]},
                )

            self.store.append_event(
                run_id,
                phase="remediation",
                kind="isolated_patch_started",
                payload={"finding_id": finding.finding_id},
            )
            bundle = FastAPIBOLAPatcher().create_bundle(
                finding,
                repository,
                self.workspace_root / run_id,
            )
            report = verify_python_project(bundle.patched_root)
            patch_verdict = (
                SecurityVerdict.SAFE if report.exit_code == 0 else SecurityVerdict.BLOCKED
            )
            self.store.append_event(
                run_id,
                phase="verification",
                kind="patch_verified" if report.exit_code == 0 else "patch_rejected",
                payload={
                    "patch_sha256": bundle.patch_sha256,
                    "exit_code": report.exit_code,
                    "duration_ms": report.duration_ms,
                },
            )
            return self.store.update_run(
                run_id,
                lifecycle=RunLifecycle.COMPLETED,
                patch_verdict=patch_verdict,
                result={
                    "findings": [finding.to_dict()],
                    "patch_bundle": bundle.to_dict(),
                    "verification": report.to_dict(),
                },
            )
        except Exception as error:
            self.store.append_event(
                run_id,
                phase="system",
                kind="run_failed",
                payload={"error_type": type(error).__name__},
            )
            return self.store.update_run(
                run_id,
                lifecycle=RunLifecycle.FAILED,
                patch_verdict=SecurityVerdict.FAILED,
                error=str(error),
            )

    def _authorized_repository(self, repository: Path) -> Path:
        resolved = repository.resolve()
        if not resolved.is_dir():
            raise RepositoryNotAuthorizedError(f"Repository does not exist: {resolved}")
        if not any(
            resolved == root or resolved.is_relative_to(root) for root in self.allowed_roots
        ):
            raise RepositoryNotAuthorizedError(
                f"Repository {resolved} is outside the configured allowed roots"
            )
        return resolved

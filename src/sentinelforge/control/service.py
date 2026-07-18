from __future__ import annotations

import uuid
from pathlib import Path

from sentinelforge.config import resolve_nvidia_config
from sentinelforge.control.models import (
    IntegrationHealth,
    RunLifecycle,
    RunRecord,
    SecurityVerdict,
)
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.inference import NIMPatchProposer, PatchProposer
from sentinelforge.remediation import (
    CandidateEvaluation,
    FastAPIBOLAPatcher,
    count_changed_lines,
    materialize_proposal,
    rank_candidates,
)
from sentinelforge.verification import verify_python_project


class RepositoryNotAuthorizedError(ValueError):
    pass


class DetectionRunService:
    def __init__(
        self,
        store: SQLiteRunStore,
        workspace_root: Path,
        allowed_roots: tuple[Path, ...],
        patch_proposer: PatchProposer | None = None,
    ) -> None:
        self.store = store
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.allowed_roots = tuple(root.resolve() for root in allowed_roots)
        if patch_proposer is None:
            nvidia = resolve_nvidia_config()
            patch_proposer = (
                NIMPatchProposer(
                    api_key=nvidia.api_key,
                    model=nvidia.model,
                    base_url=nvidia.base_url,
                    timeout_seconds=90,
                )
                if nvidia.configured
                else None
            )
        self.patch_proposer = patch_proposer
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
            deterministic_bundle = FastAPIBOLAPatcher().create_bundle(
                finding,
                repository,
                self.workspace_root / run_id / "candidates" / "deterministic",
            )
            deterministic_report = verify_python_project(deterministic_bundle.patched_root)
            candidates = [
                CandidateEvaluation(
                    candidate_id="deterministic-baseline",
                    source="deterministic",
                    bundle=deterministic_bundle,
                    verification=deterministic_report,
                    changed_lines=count_changed_lines(deterministic_bundle.patch_file),
                )
            ]
            candidate_results = [self._candidate_result(candidates[0])]
            integration_health = IntegrationHealth.HEALTHY

            if self.patch_proposer is not None:
                model_name = str(getattr(self.patch_proposer, "model", "configured-model"))
                self.store.append_event(
                    run_id,
                    phase="remediation",
                    kind="model_candidate_started",
                    payload={"provider": "nvidia_nim", "model": model_name},
                )
                try:
                    proposal = self.patch_proposer.propose(finding, str(repository))
                    model_bundle = materialize_proposal(
                        proposal,
                        finding,
                        repository,
                        self.workspace_root / run_id / "candidates" / "nvidia_nim",
                    )
                    model_report = verify_python_project(model_bundle.patched_root)
                    model_candidate = CandidateEvaluation(
                        candidate_id="nemotron-proposal",
                        source="nvidia_nim",
                        bundle=model_bundle,
                        verification=model_report,
                        changed_lines=count_changed_lines(model_bundle.patch_file),
                    )
                    candidates.append(model_candidate)
                    candidate_results.append(
                        self._candidate_result(model_candidate)
                        | {
                            "model": proposal.model,
                            "rationale": proposal.rationale,
                            "prompt_tokens": proposal.prompt_tokens,
                            "completion_tokens": proposal.completion_tokens,
                            "generation_latency_ms": proposal.latency_ms,
                        }
                    )
                    self.store.append_event(
                        run_id,
                        phase="verification",
                        kind=(
                            "model_candidate_verified"
                            if model_report.exit_code == 0
                            else "model_candidate_rejected"
                        ),
                        payload={
                            "provider": proposal.provider,
                            "model": proposal.model,
                            "patch_sha256": model_bundle.patch_sha256,
                            "exit_code": model_report.exit_code,
                            "duration_ms": model_report.duration_ms,
                            "generation_latency_ms": proposal.latency_ms,
                        },
                    )
                except Exception as error:
                    integration_health = IntegrationHealth.DEGRADED
                    self.store.append_event(
                        run_id,
                        phase="integration",
                        kind="model_candidate_failed",
                        payload={
                            "provider": "nvidia_nim",
                            "model": model_name,
                            "error_type": type(error).__name__,
                        },
                    )

            ranked = rank_candidates(candidates)
            selected = ranked[0]
            report = selected.verification
            bundle = selected.bundle
            patch_verdict = (
                SecurityVerdict.SAFE if report.exit_code == 0 else SecurityVerdict.BLOCKED
            )
            self.store.append_event(
                run_id,
                phase="remediation",
                kind="candidate_selected",
                payload={
                    "candidate_id": selected.candidate_id,
                    "source": selected.source,
                    "candidate_count": len(ranked),
                    "verified": report.exit_code == 0,
                    "changed_lines": selected.changed_lines,
                },
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
                integration_health=integration_health,
                result={
                    "findings": [finding.to_dict()],
                    "patch_bundle": bundle.to_dict(),
                    "verification": report.to_dict(),
                    "selected_candidate_id": selected.candidate_id,
                    "candidates": candidate_results,
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

    @staticmethod
    def _candidate_result(candidate: CandidateEvaluation) -> dict[str, object]:
        return {
            "candidate_id": candidate.candidate_id,
            "source": candidate.source,
            "verified": candidate.verification.exit_code == 0,
            "changed_lines": candidate.changed_lines,
            "patch_bundle": candidate.bundle.to_dict(),
            "verification": candidate.verification.to_dict(),
        }

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

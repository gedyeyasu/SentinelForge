from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelforge.domain import Finding
from sentinelforge.inference import NIMPatchProposer
from sentinelforge.remediation import (
    CandidateEvaluation,
    FastAPIBOLAPatcher,
    count_changed_lines,
    materialize_proposal,
    rank_candidates,
)
from sentinelforge.verification import verify_python_project


@dataclass
class CodeWorkResult:
    finding: Finding
    patch_bundle: Any
    verification: Any
    changed_lines: int
    patch_sha256: str
    model_used: str
    provider: str
    latency_ms: int
    files_changed: list[str]


class CodeWorkerAgent:
    """
    NemoClaw Agent that works on the code - per user request:
    'make sure we have nemo claw setup to setup an agent that works on the code'

    This agent takes a confirmed finding (e.g., BOLA) and works on the codebase to generate
    a minimal patch that fixes it, with regression test, in isolated worktree.

    Demonstrates: patch_engineer role in agents.yaml - works on code, not just scans
    """

    AGENT_ROLE = "patch_engineer"  # or code_worker

    def __init__(
        self,
        nim_proposer: NIMPatchProposer | None = None,
        vllm_proposer: Any | None = None,
    ) -> None:
        self.nim_proposer = nim_proposer
        self.vllm_proposer = vllm_proposer

    def work_on_code(
        self,
        finding: Finding,
        repository_root: Path,
        run_root: Path,
        use_nemotron: bool = True,
    ) -> list[CodeWorkResult]:
        """
        Work on code to fix vulnerability - generates competing patch candidates:
        1. Deterministic baseline (fast, explainable)
        2. Nemotron via NIM (AI-powered, minimal blast radius)
        3. vLLM via local (performance path, concurrent)

        Returns ranked candidates.
        """
        results: list[CodeWorkResult] = []
        run_root = run_root.resolve()
        run_root.mkdir(parents=True, exist_ok=True)

        # Candidate 1: Deterministic baseline - fast, explainable, no LLM
        start = time.monotonic()
        deterministic_bundle = FastAPIBOLAPatcher().create_bundle(
            finding, repository_root, run_root / "deterministic"
        )
        det_report = verify_python_project(deterministic_bundle.patched_root, timeout_seconds=90)
        det_latency = int((time.monotonic() - start) * 1000)

        results.append(
            CodeWorkResult(
                finding=finding,
                patch_bundle=deterministic_bundle,
                verification=det_report,
                changed_lines=count_changed_lines(deterministic_bundle.patch_file),
                patch_sha256=deterministic_bundle.patch_sha256,
                model_used="deterministic-baseline",
                provider="deterministic",
                latency_ms=det_latency,
                files_changed=[finding.path, f"tests/test_security_{finding.finding_id}.py"],
            )
        )

        # Candidate 2: Nemotron via NIM (if configured)
        if use_nemotron and self.nim_proposer:
            try:
                start = time.monotonic()
                proposal = self.nim_proposer.propose(finding, str(repository_root))
                model_bundle = materialize_proposal(proposal, finding, repository_root, run_root / "nvidia_nim")
                model_report = verify_python_project(model_bundle.patched_root, timeout_seconds=90)
                model_latency = int((time.monotonic() - start) * 1000)

                results.append(
                    CodeWorkResult(
                        finding=finding,
                        patch_bundle=model_bundle,
                        verification=model_report,
                        changed_lines=count_changed_lines(model_bundle.patch_file),
                        patch_sha256=model_bundle.patch_sha256,
                        model_used=proposal.model,
                        provider="nvidia_nim",
                        latency_ms=model_latency,
                        files_changed=[f.path for f in proposal.files],
                    )
                )
            except Exception as e:
                # NIM failure - keep deterministic as fallback per PLAN §17
                print(f"NIM proposer failed: {e}, using deterministic baseline")

        # Candidate 3: vLLM via local (if available)
        if use_nemotron and self.vllm_proposer:
            try:
                start = time.monotonic()
                proposal = self.vllm_proposer.propose(finding, str(repository_root))
                vllm_bundle = materialize_proposal(proposal, finding, repository_root, run_root / "vllm")
                vllm_report = verify_python_project(vllm_bundle.patched_root, timeout_seconds=90)
                vllm_latency = int((time.monotonic() - start) * 1000)

                results.append(
                    CodeWorkResult(
                        finding=finding,
                        patch_bundle=vllm_bundle,
                        verification=vllm_report,
                        changed_lines=count_changed_lines(vllm_bundle.patch_file),
                        patch_sha256=vllm_bundle.patch_sha256,
                        model_used=proposal.model,
                        provider="vllm",
                        latency_ms=vllm_latency,
                        files_changed=[f.path for f in proposal.files],
                    )
                )
            except Exception as e:
                print(f"vLLM proposer failed: {e}")

        return results

    def rank_and_select(self, results: list[CodeWorkResult]) -> CodeWorkResult | None:
        """Rank candidates per PLAN §7.4: verified first, fewer files, fewer lines, duration"""
        # Convert to CandidateEvaluation for ranking
        evals = []
        for i, r in enumerate(results):
            evals.append(
                CandidateEvaluation(
                    candidate_id=f"candidate_{i}_{r.provider}",
                    source=r.provider,
                    bundle=r.patch_bundle,
                    verification=r.verification,
                    changed_lines=r.changed_lines,
                )
            )

        ranked = rank_candidates(evals)
        for eval_result in ranked:
            if eval_result.verification.exit_code == 0:
                # Return corresponding CodeWorkResult
                for r in results:
                    if r.patch_bundle.patch_sha256 == eval_result.bundle.patch_sha256:
                        return r
        return None

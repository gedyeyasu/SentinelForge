from pathlib import Path

from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.domain import VerificationReport, VerificationStatus
from sentinelforge.inference import PatchProposal, ProposedFile
from sentinelforge.remediation import (
    CandidateEvaluation,
    FastAPIBOLAPatcher,
    UnsafePatchProposalError,
    count_changed_lines,
    materialize_proposal,
    rank_candidates,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
FIXTURE = REPOSITORY_ROOT / "examples" / "vulnerable_shop"


def test_model_proposal_is_materialized_only_inside_isolated_workspace(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    baseline = FastAPIBOLAPatcher().create_bundle(finding, FIXTURE, tmp_path / "baseline")
    proposal = PatchProposal(
        finding_id=finding.finding_id,
        provider="nvidia_nim",
        model="test-model",
        rationale="Use the verified tenant guard.",
        files=[
            ProposedFile(
                path=finding.path,
                content=(baseline.patched_root / finding.path).read_text(encoding="utf-8"),
            ),
            ProposedFile(
                path="tests/test_security_model.py",
                content=baseline.regression_test.read_text(encoding="utf-8"),
            ),
        ],
        latency_ms=12,
    )

    bundle = materialize_proposal(proposal, finding, FIXTURE, tmp_path / "model")

    assert bundle.patched_root.is_relative_to(tmp_path)
    assert "order.tenant_id != current_user.tenant_id" in (
        bundle.patched_root / finding.path
    ).read_text(encoding="utf-8")
    assert len(bundle.patch_sha256) == 64


def test_model_proposal_cannot_write_outside_source_and_tests(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    proposal = PatchProposal(
        finding_id=finding.finding_id,
        provider="nvidia_nim",
        model="test-model",
        rationale="Attempt an unrelated change.",
        files=[
            ProposedFile(path="../../.env", content="SECRET=stolen"),
            ProposedFile(path=finding.path, content="pass"),
        ],
        latency_ms=12,
    )

    try:
        materialize_proposal(proposal, finding, FIXTURE, tmp_path / "model")
    except UnsafePatchProposalError as error:
        assert "Unsafe proposal path" in str(error)
    else:
        raise AssertionError("Path-traversal proposal was accepted")


def test_candidate_ranking_prefers_verified_minimal_patch(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    baseline = FastAPIBOLAPatcher().create_bundle(finding, FIXTURE, tmp_path / "baseline")
    passed = VerificationReport(
        status=VerificationStatus.PASSED,
        command=("pytest",),
        exit_code=0,
        duration_ms=100,
        stdout="passed",
        stderr="",
    )
    failed = VerificationReport(
        status=VerificationStatus.FAILED,
        command=("pytest",),
        exit_code=1,
        duration_ms=50,
        stdout="failed",
        stderr="",
    )
    candidates = [
        CandidateEvaluation("fast-but-broken", "model", baseline, failed, 2),
        CandidateEvaluation(
            "verified-baseline",
            "deterministic",
            baseline,
            passed,
            count_changed_lines(baseline.patch_file),
        ),
    ]

    ranked = rank_candidates(candidates)

    assert ranked[0].candidate_id == "verified-baseline"

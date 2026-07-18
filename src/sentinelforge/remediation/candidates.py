from __future__ import annotations

import difflib
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path

from sentinelforge.domain import Finding, PatchBundle, VerificationReport
from sentinelforge.inference import PatchProposal


class UnsafePatchProposalError(ValueError):
    pass


@dataclass(frozen=True)
class CandidateEvaluation:
    candidate_id: str
    source: str
    bundle: PatchBundle
    verification: VerificationReport
    changed_lines: int


def materialize_proposal(
    proposal: PatchProposal,
    finding: Finding,
    source_root: Path,
    run_root: Path,
) -> PatchBundle:
    if proposal.finding_id != finding.finding_id:
        raise UnsafePatchProposalError("Proposal finding does not match requested finding")
    source_root = source_root.resolve()
    run_root = run_root.resolve()
    patched_root = run_root / "patched"
    if patched_root.exists():
        raise UnsafePatchProposalError("Candidate workspace already exists")
    run_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_root, patched_root)

    total_bytes = sum(len(item.content.encode()) for item in proposal.files)
    if total_bytes > 100_000:
        raise UnsafePatchProposalError("Proposal exceeds the 100 KB candidate limit")

    changed_files: list[str] = []
    diff_parts: list[str] = []
    regression_test: Path | None = None
    for item in proposal.files:
        relative = _safe_relative_path(item.path)
        if relative.as_posix() != finding.path and relative.parts[0] != "tests":
            raise UnsafePatchProposalError(
                f"Proposal may change only {finding.path} and tests/, not {relative}"
            )
        destination = (patched_root / relative).resolve()
        if not destination.is_relative_to(patched_root):
            raise UnsafePatchProposalError("Proposal path escapes the isolated workspace")
        original_path = source_root / relative
        original = original_path.read_text(encoding="utf-8") if original_path.exists() else ""
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(item.content, encoding="utf-8")
        changed_files.append(relative.as_posix())
        if relative.parts[0] == "tests" and regression_test is None:
            regression_test = destination
        diff_parts.extend(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                item.content.splitlines(keepends=True),
                fromfile=f"a/{relative.as_posix()}" if original else "/dev/null",
                tofile=f"b/{relative.as_posix()}",
            )
        )

    if finding.path not in changed_files:
        raise UnsafePatchProposalError("Proposal does not modify the vulnerable source file")
    if regression_test is None:
        raise UnsafePatchProposalError("Proposal does not include a regression test under tests/")
    diff = "".join(diff_parts)
    if not diff:
        raise UnsafePatchProposalError("Proposal does not change any content")
    patch_file = run_root / "remediation.patch"
    patch_file.write_text(diff, encoding="utf-8")
    return PatchBundle(
        finding_id=finding.finding_id,
        source_root=source_root,
        patched_root=patched_root,
        patch_file=patch_file,
        regression_test=regression_test,
        changed_files=tuple(changed_files),
        patch_sha256=hashlib.sha256(diff.encode()).hexdigest(),
    )


def rank_candidates(candidates: list[CandidateEvaluation]) -> list[CandidateEvaluation]:
    return sorted(
        candidates,
        key=lambda item: (
            item.verification.exit_code != 0,
            len(item.bundle.changed_files),
            item.changed_lines,
            item.verification.duration_ms,
            item.candidate_id,
        ),
    )


def count_changed_lines(patch_file: Path) -> int:
    return sum(
        1
        for line in patch_file.read_text(encoding="utf-8").splitlines()
        if (line.startswith("+") or line.startswith("-"))
        and not line.startswith("+++")
        and not line.startswith("---")
    )


def _safe_relative_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise UnsafePatchProposalError(f"Unsafe proposal path: {raw_path}")
    return path

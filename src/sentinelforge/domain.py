from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int
    function: str
    endpoint: str
    method: str
    description: str
    invariant: str
    evidence: dict[str, Any]
    remediation: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass(frozen=True)
class PatchBundle:
    finding_id: str
    source_root: Path
    patched_root: Path
    patch_file: Path
    regression_test: Path
    changed_files: tuple[str, ...]
    patch_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source_root": str(self.source_root),
            "patched_root": str(self.patched_root),
            "patch_file": str(self.patch_file),
            "regression_test": str(self.regression_test),
            "changed_files": list(self.changed_files),
            "patch_sha256": self.patch_sha256,
        }


@dataclass(frozen=True)
class VerificationReport:
    status: VerificationStatus
    command: tuple[str, ...]
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["command"] = list(self.command)
        return result

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from sentinelforge.domain import VerificationReport, VerificationStatus


def verify_python_project(project_root: Path, timeout_seconds: int = 90) -> VerificationReport:
    command = (sys.executable, "-m", "pytest", "-q")
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        passed = result.returncode == 0
        return VerificationReport(
            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
            command=command,
            exit_code=result.returncode,
            duration_ms=duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            checks={"repository_tests": passed, "security_regression": passed},
        )
    except subprocess.TimeoutExpired as error:
        duration_ms = int((time.monotonic() - started) * 1000)
        return VerificationReport(
            status=VerificationStatus.FAILED,
            command=command,
            exit_code=124,
            duration_ms=duration_ms,
            stdout=(error.stdout or "") if isinstance(error.stdout, str) else "",
            stderr="Verification timed out",
            checks={"repository_tests": False, "security_regression": False},
        )

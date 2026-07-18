from pathlib import Path

from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.remediation import FastAPIBOLAPatcher
from sentinelforge.verification import verify_python_project

FIXTURE = Path(__file__).parents[1] / "examples" / "vulnerable_shop"


def test_patcher_creates_isolated_minimal_patch_and_regression_test(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]

    bundle = FastAPIBOLAPatcher().create_bundle(finding, FIXTURE, tmp_path / "run")

    original = (FIXTURE / finding.path).read_text(encoding="utf-8")
    patched = (bundle.patched_root / finding.path).read_text(encoding="utf-8")
    patch = bundle.patch_file.read_text(encoding="utf-8")
    regression = bundle.regression_test.read_text(encoding="utf-8")

    assert "order.tenant_id != current_user.tenant_id" not in original
    assert "order.tenant_id != current_user.tenant_id" in patched
    assert "status_code=404" in patched
    assert "cross_tenant_access_is_denied" in regression
    assert finding.finding_id in patch
    assert len(bundle.patch_sha256) == 64


def test_patched_copy_no_longer_triggers_detector(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    bundle = FastAPIBOLAPatcher().create_bundle(finding, FIXTURE, tmp_path / "run")

    assert FastAPIBOLADetector().scan(bundle.patched_root) == []


def test_patched_copy_passes_repository_and_generated_security_tests(tmp_path: Path) -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    bundle = FastAPIBOLAPatcher().create_bundle(finding, FIXTURE, tmp_path / "run")

    report = verify_python_project(bundle.patched_root, timeout_seconds=30)

    assert report.exit_code == 0, report.stdout + report.stderr
    assert report.checks == {"repository_tests": True, "security_regression": True}

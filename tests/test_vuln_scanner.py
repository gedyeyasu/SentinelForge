from pathlib import Path

from sentinelforge.agents.dependencies import DependencyParser
from sentinelforge.agents.vuln_scanner import DependencyVulnerabilityScanner
from sentinelforge.integrations.red_hat import RedHatAdvisory


def _make_advisory(package: str = "fastapi") -> RedHatAdvisory:
    return RedHatAdvisory(
        advisory_id="RHSA-2024-0001",
        severity="critical",
        released_on="2024-01-15",
        cves=("CVE-2024-12345",),
        released_packages=(
            f"python-{package}-0.100.0",
        ),
        resource_url=(
            "https://access.redhat.com/errata/RHSA-2024-0001"
        ),
    )


class _StubClient:
    def __init__(
        self, advisories: list[RedHatAdvisory]
    ) -> None:
        self._advisories = advisories

    def list_advisories(
        self, **kwargs: object
    ) -> list[RedHatAdvisory]:
        return self._advisories


def test_scanner_finds_vulnerability(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\ndependencies = ["fastapi>=0.100"]\n',
        encoding="utf-8",
    )
    manifest = DependencyParser().parse_project(tmp_path)
    assert len(manifest.dependencies) == 1

    advisory = _make_advisory("fastapi")
    stub = _StubClient([advisory])

    scanner = DependencyVulnerabilityScanner(
        red_hat_client=stub  # type: ignore[arg-type]
    )
    result = scanner.scan(manifest)

    assert result.unique_packages == 1
    assert len(result.vulnerabilities) >= 1


def test_scanner_handles_empty_manifest(
    tmp_path: Path,
) -> None:
    manifest = DependencyParser().parse_project(tmp_path)

    stub = _StubClient([])

    scanner = DependencyVulnerabilityScanner(
        red_hat_client=stub  # type: ignore[arg-type]
    )
    result = scanner.scan(manifest)

    assert result.unique_packages == 0
    assert len(result.vulnerabilities) == 0


def test_scanner_result_to_dict(tmp_path: Path) -> None:
    manifest = DependencyParser().parse_project(tmp_path)

    stub = _StubClient([])

    scanner = DependencyVulnerabilityScanner(
        red_hat_client=stub  # type: ignore[arg-type]
    )
    result = scanner.scan(manifest)

    d = result.to_dict()
    assert "vulnerable_count" in d
    assert "critical_count" in d

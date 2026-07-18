from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sentinelforge.agents.dependencies import Dependency, DependencyManifest
from sentinelforge.integrations.red_hat import RedHatAdvisory, RedHatSecurityDataClient


class VulnSeverity(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MODERATE = "moderate"
    IMPORTANT = "important"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DependencyVulnerability:
    dependency: str
    installed_version: str
    advisory_id: str
    severity: str
    cves: tuple[str, ...]
    description: str
    fix_versions: tuple[str, ...]
    confidence: float
    reachable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency": self.dependency,
            "installed_version": self.installed_version,
            "advisory_id": self.advisory_id,
            "severity": self.severity,
            "cves": list(self.cves),
            "description": self.description,
            "fix_versions": list(self.fix_versions),
            "confidence": self.confidence,
            "reachable": self.reachable,
        }


@dataclass(frozen=True)
class DependencyScanResult:
    manifest_dependencies: int
    unique_packages: int
    advisories_checked: int
    vulnerabilities: tuple[DependencyVulnerability, ...]
    scan_errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_dependencies": self.manifest_dependencies,
            "unique_packages": self.unique_packages,
            "advisories_checked": self.advisories_checked,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_errors": list(self.scan_errors),
            "vulnerable_count": len(self.vulnerabilities),
            "critical_count": sum(
                1 for v in self.vulnerabilities if v.severity == "critical"
            ),
        }


class DependencyVulnerabilityScanner:
    def __init__(
        self,
        red_hat_client: RedHatSecurityDataClient | None = None,
        *,
        lookback_days: int = 365,
        per_page: int = 25,
    ) -> None:
        self._red_hat = red_hat_client or RedHatSecurityDataClient()
        self._lookback_days = lookback_days
        self._per_page = per_page

    def scan(
        self,
        manifest: DependencyManifest,
        *,
        repository_root: str | None = None,
        progress_callback=None,
    ) -> DependencyScanResult:
        unique_names = manifest.unique_names()
        all_vulns: list[DependencyVulnerability] = []
        errors: list[str] = []
        advisory_count = 0

        dep_map: dict[str, Dependency] = {}
        for dep in manifest.all_dependencies:
            dep_map[dep.normalized_name] = dep

        if progress_callback:
            progress_callback("started", {
                "unique_packages": len(unique_names),
                "total_deps": len(manifest.all_dependencies),
            })

        for pkg_idx, name in enumerate(unique_names, 1):
            dep = dep_map.get(name)
            version = dep.version_constraint if dep else ""

            if progress_callback:
                progress_callback("checking_package", {
                    "package": name,
                    "version": version,
                    "package_index": pkg_idx,
                    "total_packages": len(unique_names),
                })

            try:
                advisories = self._red_hat.list_advisories(
                    package=name,
                    created_days_ago=self._lookback_days,
                    per_page=self._per_page,
                )
                advisory_count += len(advisories)
            except Exception as error:
                errors.append(f"Red Hat query failed for {name}: {error}")
                if progress_callback:
                    progress_callback("package_error", {
                        "package": name,
                        "error": str(error),
                    })
                continue

            pkg_vulns = 0
            for advisory in advisories:
                vuln = self._evaluate_advisory(name, version, advisory, repository_root)
                if vuln is not None:
                    all_vulns.append(vuln)
                    pkg_vulns += 1
                    if progress_callback:
                        progress_callback("vuln_found", {
                            "package": name,
                            "advisory_id": advisory.advisory_id,
                            "severity": advisory.severity,
                            "cves": advisory.cves,
                            "description": advisory.description[:100],
                        })

            if progress_callback:
                progress_callback("package_complete", {
                    "package": name,
                    "advisories_checked": len(advisories),
                    "vulnerabilities": pkg_vulns,
                })

        all_vulns.sort(key=lambda v: (v.severity, v.dependency), reverse=True)

        if progress_callback:
            progress_callback("completed", {
                "unique_packages": len(unique_names),
                "advisories_checked": advisory_count,
                "vulnerability_count": len(all_vulns),
                "error_count": len(errors),
            })

        return DependencyScanResult(
            manifest_dependencies=len(manifest.all_dependencies),
            unique_packages=len(unique_names),
            advisories_checked=advisory_count,
            vulnerabilities=tuple(all_vulns),
            scan_errors=tuple(errors),
        )

    def _evaluate_advisory(
        self,
        package_name: str,
        installed_version: str,
        advisory: RedHatAdvisory,
        repository_root: str | None,
    ) -> DependencyVulnerability | None:
        severity = advisory.severity.lower()
        if severity not in ("low", "moderate", "important", "critical"):
            severity = "moderate"

        confidence = self._version_match_confidence(installed_version, advisory)
        if confidence < 0.3:
            return None

        reachable = False
        if repository_root:
            reachable = self._check_reachability(
                package_name, repository_root, advisory.cves
            )

        description_parts = []
        if advisory.cves:
            description_parts.append(f"CVEs: {', '.join(advisory.cves[:3])}")
        if advisory.released_packages:
            description_parts.append(
                f"Affected: {', '.join(advisory.released_packages[:2])}"
            )

        return DependencyVulnerability(
            dependency=package_name,
            installed_version=installed_version,
            advisory_id=advisory.advisory_id,
            severity=severity,
            cves=tuple(advisory.cves),
            description="; ".join(description_parts) if description_parts else "Advisory found",
            fix_versions=tuple(advisory.released_packages[:2]),
            confidence=confidence,
            reachable=reachable,
        )

    @staticmethod
    def _version_match_confidence(version: str, advisory: RedHatAdvisory) -> float:
        if not version:
            return 0.5

        cleaned = re.sub(r"[><=!~]", "", version).strip()
        if not cleaned:
            return 0.5

        pkg_match = any(
            cleaned.lower() in pkg.lower() or pkg.lower() in cleaned.lower()
            for pkg in advisory.released_packages
        )
        if pkg_match:
            return 0.85

        return 0.55

    @staticmethod
    def _check_reachability(
        package_name: str,
        repository_root: str,
        cves: list[str],
    ) -> bool:
        from pathlib import Path

        root = Path(repository_root).resolve()
        patterns = [
            re.compile(rf"import\s+{re.escape(package_name)}", re.IGNORECASE),
            re.compile(rf"from\s+{re.escape(package_name)}", re.IGNORECASE),
            re.compile(rf'"{re.escape(package_name)}"', re.IGNORECASE),
            re.compile(rf"'{re.escape(package_name)}'", re.IGNORECASE),
        ]

        for py_file in root.rglob("*.py"):
            if any(part.startswith(".") for part in py_file.relative_to(root).parts):
                continue
            if "__pycache__" in py_file.parts:
                continue
            try:
                content = py_file.read_text(encoding="utf-8")
            except OSError:
                continue
            for pattern in patterns:
                if pattern.search(content):
                    return True
        return False

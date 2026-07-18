from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class SBOMComponent:
    name: str
    version: str | None
    purl: str | None
    type: str = "library"
    normalized_name: str = ""

    def __post_init__(self):
        object.__setattr__(self, "normalized_name", self._normalize(self.name))

    @staticmethod
    def _normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name.lower()).strip("-")

    def version_matches(self, spec: str) -> bool:
        if not spec or not self.version:
            return True
        try:
            v = Version(self.version)
            # Simple range handling: >=, <=, ==, <, >
            if spec.startswith(">="):
                return v >= Version(spec[2:].strip())
            if spec.startswith("<="):
                return v <= Version(spec[2:].strip())
            if spec.startswith("=="):
                return v == Version(spec[2:].strip())
            if spec.startswith(">"):
                return v > Version(spec[1:].strip())
            if spec.startswith("<"):
                return v < Version(spec[1:].strip())
            # exact match fallback
            return self.version == spec
        except InvalidVersion:
            return self.version in spec or spec in self.version


@dataclass
class SBOM:
    bom_format: str
    spec_version: str | None
    components: list[SBOMComponent]
    metadata: dict[str, Any] = None

    @property
    def unique_packages(self) -> int:
        return len({c.normalized_name for c in self.components})


class SBOMParser:
    """Parse CycloneDX and SPDX SBOMs, plus fallback to pyproject/requirements."""

    def parse_file(self, path: Path) -> SBOM | None:
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        # CycloneDX detection
        if data.get("bomFormat") == "CycloneDX" or "components" in data:
            return self._parse_cyclonedx(data)
        # SPDX detection
        if data.get("spdxVersion") or "packages" in data:
            return self._parse_spdx(data)
        return None

    def parse_project(self, root: Path) -> SBOM:
        # Look for sbom files first
        candidates = [
            root / "bom.json",
            root / "sbom.json",
            root / "cyclonedx.json",
            root / "cyclonedx.bom.json",
        ]
        for p in candidates:
            sbom = self.parse_file(p)
            if sbom:
                return sbom
        # Fallback to dependency parser results via SBOM
        from sentinelforge.agents.dependencies import DependencyParser

        manifest = DependencyParser().parse_project(root)
        components = [
            SBOMComponent(name=pkg, version=ver, purl=f"pkg:pypi/{pkg}@{ver}" if ver else None)
            for pkg, ver in manifest.items()  # type: ignore
        ] if hasattr(manifest, "items") else []
        # manifest is actually dict-like? Let's handle
        if not components:
            # manifest is DependencyManifest with packages attr
            try:
                comps = []
                for dep in manifest.packages:  # type: ignore
                    comps.append(SBOMComponent(name=dep.name, version=dep.version, purl=None))
                components = comps
            except AttributeError:
                pass

        return SBOM(bom_format="ParsedDependencies", spec_version=None, components=components, metadata={})

    def _parse_cyclonedx(self, data: dict[str, Any]) -> SBOM:
        comps = []
        for c in data.get("components", []):
            name = c.get("name") or c.get("purl", "").split("/")[-1].split("@")[0]
            version = c.get("version")
            purl = c.get("purl")
            ctype = c.get("type", "library")
            if name:
                comps.append(SBOMComponent(name=name, version=version, purl=purl, type=ctype))
        return SBOM(
            bom_format=data.get("bomFormat", "CycloneDX"),
            spec_version=data.get("specVersion"),
            components=comps,
            metadata=data.get("metadata", {}),
        )

    def _parse_spdx(self, data: dict[str, Any]) -> SBOM:
        comps = []
        for pkg in data.get("packages", []):
            name = pkg.get("name") or pkg.get("SPDXID")
            version = pkg.get("versionInfo")
            purl = None
            # Try to find purl from external refs
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
            if name and name != "NOASSERTION":
                comps.append(SBOMComponent(name=name, version=version, purl=purl))
        return SBOM(
            bom_format="SPDX",
            spec_version=data.get("spdxVersion"),
            components=comps,
            metadata={},
        )

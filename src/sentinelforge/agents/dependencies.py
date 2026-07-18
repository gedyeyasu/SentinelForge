from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    name: str
    version_constraint: str
    source_file: str

    @property
    def normalized_name(self) -> str:
        return re.sub(r"[-_.]+", "-", self.name).lower()


@dataclass
class DependencyManifest:
    dependencies: list[Dependency] = field(default_factory=list)
    dev_dependencies: list[Dependency] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def all_dependencies(self) -> list[Dependency]:
        return self.dependencies + self.dev_dependencies

    def unique_names(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for dep in self.all_dependencies:
            normalized = dep.normalized_name
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return sorted(result)


class DependencyParser:
    def parse_project(self, root: Path) -> DependencyManifest:
        root = root.resolve()
        manifest = DependencyManifest()

        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            self._parse_pyproject(pyproject, manifest)

        for name in ("requirements.txt", "requirements.in"):
            req_file = root / name
            if req_file.is_file():
                self._parse_requirements(req_file, manifest)

        for req_file in sorted(root.rglob("requirements*.txt")):
            if req_file == root / "requirements.txt":
                continue
            self._parse_requirements(req_file, manifest)

        return manifest

    def _parse_pyproject(self, path: Path, manifest: DependencyManifest) -> None:
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError) as error:
            manifest.parse_errors.append(f"pyproject.toml: {error}")
            return

        project = raw.get("project", {})
        for dep_str in project.get("dependencies", []):
            parsed = self._parse_dep_string(dep_str, "pyproject.toml")
            if parsed:
                manifest.dependencies.append(parsed)

        optional = project.get("optional-dependencies", {})
        for group_deps in optional.values():
            for dep_str in group_deps:
                parsed = self._parse_dep_string(dep_str, "pyproject.toml")
                if parsed:
                    manifest.dev_dependencies.append(parsed)

    def _parse_requirements(self, path: Path, manifest: DependencyManifest) -> None:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            manifest.parse_errors.append(f"{path.name}: {error}")
            return

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            parsed = self._parse_dep_string(stripped, path.name)
            if parsed:
                manifest.dependencies.append(parsed)

    @staticmethod
    def _parse_dep_string(dep_str: str, source: str) -> Dependency | None:
        cleaned = dep_str.strip()
        if not cleaned or cleaned.startswith("#"):
            return None

        match = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(.*)",
            cleaned,
        )
        if not match:
            return None

        name = match.group(1)
        version = match.group(3).strip() if match.group(3) else ""
        version = re.split(r"\s+(?:;|#$)", version, maxsplit=1)[0].strip()
        return Dependency(name=name, version_constraint=version, source_file=source)

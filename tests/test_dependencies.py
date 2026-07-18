from pathlib import Path

from sentinelforge.agents.dependencies import DependencyParser


def test_parser_reads_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """\
[project]
dependencies = [
    "fastapi>=0.100",
    "httpx>=0.24",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
]
""",
        encoding="utf-8",
    )

    manifest = DependencyParser().parse_project(tmp_path)

    assert len(manifest.dependencies) == 2
    assert len(manifest.dev_dependencies) == 1
    assert manifest.dependencies[0].name == "fastapi"
    assert manifest.dependencies[1].name == "httpx"
    assert manifest.dev_dependencies[0].name == "pytest"


def test_parser_reads_requirements_txt(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text(
        "fastapi>=0.100\nhttpx>=0.24\n# comment\n",
        encoding="utf-8",
    )

    manifest = DependencyParser().parse_project(tmp_path)

    assert len(manifest.dependencies) == 2
    names = [d.name for d in manifest.dependencies]
    assert "fastapi" in names
    assert "httpx" in names


def test_parser_unique_names(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """\
[project]
dependencies = ["fastapi>=0.100", "httpx>=0.24"]

[project.optional-dependencies]
dev = ["pytest>=8.0", "httpx>=0.24"]
""",
        encoding="utf-8",
    )

    manifest = DependencyParser().parse_project(tmp_path)
    unique = manifest.unique_names()

    assert "fastapi" in unique
    assert "httpx" in unique
    assert "pytest" in unique
    assert len(unique) == 3


def test_parser_handles_missing_files(tmp_path: Path) -> None:
    manifest = DependencyParser().parse_project(tmp_path)
    assert manifest.dependencies == []
    assert manifest.dev_dependencies == []


def test_parser_handles_invalid_toml(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("invalid [[[", encoding="utf-8")

    manifest = DependencyParser().parse_project(tmp_path)
    assert len(manifest.parse_errors) == 1


def test_parser_normalized_name() -> None:
    dep = DependencyParser._parse_dep_string(
        "My-Package.Name>=1.0", "test"
    )
    assert dep is not None
    assert dep.normalized_name == "my-package-name"

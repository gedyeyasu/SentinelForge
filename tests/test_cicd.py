from __future__ import annotations

from pathlib import Path

from sentinelforge.cicd import CICDGenerator


def test_generate_github_actions(tmp_path: Path) -> None:
    path = CICDGenerator.generate_github_actions(tmp_path)
    assert path.exists()
    content = path.read_text()
    assert "SentinelForge Security Scan" in content
    assert "sentinelforge scan ." in content
    assert ".github/workflows/sentinelforge.yml" == str(path.relative_to(tmp_path))


def test_generate_github_actions_custom_cron(tmp_path: Path) -> None:
    path = CICDGenerator.generate_github_actions(
        tmp_path, schedule_cron="30 4 * * 1"
    )
    content = path.read_text()
    assert "30 4 * * 1" in content


def test_generate_github_actions_custom_mode(tmp_path: Path) -> None:
    path = CICDGenerator.generate_github_actions(
        tmp_path, pentest_mode="full"
    )
    content = path.read_text()
    assert "default: 'full'" in content


def test_generate_gitlab_ci(tmp_path: Path) -> None:
    path = CICDGenerator.generate_gitlab_ci(tmp_path)
    assert path.exists()
    content = path.read_text()
    assert "sentinelforge-scan:" in content
    assert "sentinelforge-pentest:" in content
    assert "sentinelforge scan ." in content


def test_generate_pre_commit_config(tmp_path: Path) -> None:
    path = CICDGenerator.generate_pre_commit_config(tmp_path)
    assert path.exists()
    content = path.read_text()
    assert "sentinelforge-scan" in content
    assert "sentinelforge scan ." in content
    assert "pre-commit" in content


def test_generate_all_three(tmp_path: Path) -> None:
    gh = CICDGenerator.generate_github_actions(tmp_path)
    gl = CICDGenerator.generate_gitlab_ci(tmp_path)
    pc = CICDGenerator.generate_pre_commit_config(tmp_path)
    assert gh.exists()
    assert gl.exists()
    assert pc.exists()

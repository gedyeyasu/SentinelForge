from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinelforge.pr_generator import PRGenerator, PullRequest


def test_pull_request_to_dict() -> None:
    pr = PullRequest(
        number=42,
        url="https://github.com/org/repo/pull/42",
        title="Fix security issue",
        branch="sentinelforge/fix/sf-py-001",
        body="## Security Fix\nPatch applied.",
    )
    d = pr.to_dict()
    assert d["number"] == 42
    assert d["url"] == "https://github.com/org/repo/pull/42"
    assert d["title"] == "Fix security issue"
    assert d["branch"] == "sentinelforge/fix/sf-py-001"


def test_generate_branch_name() -> None:
    gen = PRGenerator()
    branch = gen.generate_branch_name({
        "rule_id": "sf-py-injection",
        "finding_id": "abc123456789",
    })
    assert branch == "sentinelforge/injection/abc12345"


def test_generate_branch_name_default() -> None:
    gen = PRGenerator()
    branch = gen.generate_branch_name({})
    assert branch.startswith("sentinelforge/")


def test_generate_pr_body_minimal() -> None:
    gen = PRGenerator()
    body = gen.generate_pr_body({
        "severity": "critical",
        "rule_id": "sf-py-injection",
        "description": "SQL injection found",
        "endpoint": "/api/users",
        "remediation": "Use parameterized queries",
    })
    assert "CRITICAL" in body
    assert "sf-py-injection" in body
    assert "/api/users" in body
    assert "Use parameterized queries" in body
    assert "SentinelForge" in body


def test_generate_pr_body_with_patch_sha() -> None:
    gen = PRGenerator()
    body = gen.generate_pr_body(
        {"severity": "high", "rule_id": "sf-py-xss"},
        patch_sha256="abc123def456",
        verification_passed=True,
    )
    assert "abc123def456" in body
    assert "Yes" in body


def test_generate_pr_body_pending_verification() -> None:
    gen = PRGenerator()
    body = gen.generate_pr_body(
        {"severity": "medium"},
        patch_sha256="sha",
        verification_passed=False,
    )
    assert "Pending" in body


def test_apply_patches(tmp_path: Path) -> None:
    gen = PRGenerator()
    patches = {
        "src/app.py": "print('patched')",
        "src/utils/helper.py": "def safe(): pass",
    }
    files = gen.apply_patches(tmp_path, patches)
    assert len(files) == 2
    assert (tmp_path / "src/app.py").read_text() == "print('patched')"
    assert (tmp_path / "src/utils/helper.py").read_text() == "def safe(): pass"


def test_apply_patches_empty(tmp_path: Path) -> None:
    gen = PRGenerator()
    files = gen.apply_patches(tmp_path, {})
    assert files == []


def test_create_pull_request_success(tmp_path: Path) -> None:
    gen = PRGenerator()
    with patch("sentinelforge.pr_generator.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="https://github.com/org/repo/pull/42",
        )
        pr = gen.create_pull_request(
            tmp_path,
            title="Fix",
            body="Patch applied",
            head="sentinelforge/fix/test",
        )
        assert pr is not None
        assert pr.number == 42
        assert pr.url == "https://github.com/org/repo/pull/42"
        assert pr.title == "Fix"


def test_create_pull_request_failure(tmp_path: Path) -> None:
    gen = PRGenerator()
    with patch("sentinelforge.pr_generator.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        pr = gen.create_pull_request(
            tmp_path,
            title="Fix",
            body="Patch applied",
            head="sentinelforge/fix/test",
        )
        assert pr is None

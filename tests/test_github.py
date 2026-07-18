from __future__ import annotations

from pathlib import Path

from sentinelforge.integrations.github import GitHubClient


def test_github_client_not_configured() -> None:
    client = GitHubClient(token="")
    assert not client.configured
    assert client.list_repos() == []
    assert client.health()["status"] == "not_configured"


def test_github_client_health_no_token() -> None:
    client = GitHubClient(token="")
    health = client.health()
    assert health["status"] == "not_configured"


def test_github_client_headers() -> None:
    client = GitHubClient(token="ghp_test123")
    headers = client._headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer ghp_test123"
    assert "X-GitHub-Api-Version" in headers

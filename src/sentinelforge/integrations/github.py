from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


@dataclass(frozen=True)
class GitHubRepo:
    name: str
    full_name: str
    url: str
    clone_url: str
    default_branch: str
    private: bool
    description: str
    language: str | None
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "full_name": self.full_name,
            "url": self.url,
            "clone_url": self.clone_url,
            "default_branch": self.default_branch,
            "private": self.private,
            "description": self.description,
            "language": self.language,
            "updated_at": self.updated_at,
        }


class GitHubClient:
    """GitHub API client for listing and cloning repositories."""

    def __init__(
        self,
        *,
        token: str | None = None,
        timeout_seconds: float = 30,
        client: httpx.Client | None = None,
    ) -> None:
        self._token = token or os.environ.get("GITHUB_TOKEN", "").strip()
        self._client = client or httpx.Client(timeout=timeout_seconds)

    @property
    def configured(self) -> bool:
        return bool(self._token)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def health(self) -> dict[str, object]:
        if not self.configured:
            return {"status": "not_configured", "message": "Set GITHUB_TOKEN"}
        try:
            response = self._client.get(
                "https://api.github.com/user",
                headers=self._headers(),
            )
            if response.status_code == 200:
                user = response.json()
                return {
                    "status": "authenticated",
                    "login": user.get("login"),
                    "name": user.get("name"),
                }
            return {"status": "error", "status_code": response.status_code}
        except Exception as error:
            return {"status": "error", "error": str(error)}

    def list_repos(
        self,
        *,
        owner: str | None = None,
        per_page: int = 30,
        repo_type: str = "all",
        sort: str = "updated",
    ) -> list[GitHubRepo]:
        if not self.configured:
            return []
        if owner:
            url = f"https://api.github.com/users/{owner}/repos"
        else:
            url = "https://api.github.com/user/repos"
        params = {
            "per_page": str(per_page),
            "type": repo_type,
            "sort": sort,
        }
        try:
            response = self._client.get(
                url,
                headers=self._headers(),
                params=params,
            )
            response.raise_for_status()
            repos = []
            for item in response.json():
                repos.append(
                    GitHubRepo(
                        name=item.get("name", ""),
                        full_name=item.get("full_name", ""),
                        url=item.get("html_url", ""),
                        clone_url=item.get("clone_url", ""),
                        default_branch=item.get("default_branch", "main"),
                        private=item.get("private", False),
                        description=item.get("description") or "",
                        language=item.get("language"),
                        updated_at=item.get("updated_at", ""),
                    )
                )
            return repos
        except Exception:
            return []

    def clone_repo(
        self,
        clone_url: str,
        target_dir: Path | None = None,
        branch: str | None = None,
    ) -> Path:
        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="sentinelforge_gh_"))
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        if self._token and "github.com" in clone_url:
            authenticated_url = clone_url.replace(
                "https://github.com/",
                f"https://x-access-token:{self._token}@github.com/",
            )
            cmd.extend([authenticated_url, str(target_dir)])
        else:
            cmd.extend([clone_url, str(target_dir)])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr}")
        return target_dir

    def get_repo_info(self, owner: str, repo: str) -> dict[str, Any] | None:
        if not self.configured:
            return None
        try:
            response = self._client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers=self._headers(),
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            return None

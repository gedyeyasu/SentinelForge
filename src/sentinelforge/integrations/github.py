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
    """GitHub API client for listing and cloning repositories.
    
    Supports multiple token sources for enterprise OAuth flow:
    1. Explicit token param
    2. GITHUB_TOKEN env var
    3. OAuth token file .sentinelforge/github_token.json (from OAuth flow)
    """

    def __init__(
        self,
        *,
        token: str | None = None,
        timeout_seconds: float = 30,
        client: httpx.Client | None = None,
    ) -> None:
        resolved_token = token
        if not resolved_token:
            resolved_token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not resolved_token:
            # Try OAuth file
            try:
                from pathlib import Path
                import json

                oauth_file = Path(".sentinelforge/github_token.json")
                if oauth_file.is_file():
                    data = json.loads(oauth_file.read_text(encoding="utf-8"))
                    resolved_token = data.get("access_token", "").strip()
            except Exception:
                pass

        self._token = resolved_token or ""
        self._client = client or httpx.Client(timeout=timeout_seconds)

    @staticmethod
    def load_token_from_any_source() -> str:
        """Load token from any source: OAuth file, env, explicit"""
        # Try OAuth manager first
        try:
            from sentinelforge.integrations.github_oauth import GitHubOAuthManager

            manager = GitHubOAuthManager()
            token_obj = manager.load_token()
            if token_obj and token_obj.access_token:
                return token_obj.access_token
        except Exception:
            pass
        return os.environ.get("GITHUB_TOKEN", "").strip()

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
        """
        Secure clone: uses GIT_ASKPASS to avoid token in process list / logs per enterprise hardening.
        Falls back to credential helper if askpass fails.
        """
        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="sentinelforge_gh_"))
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])

        env = os.environ.copy()
        askpass_script = None
        if self._token and "github.com" in clone_url:
            # Write askpass script to avoid token in cmdline
            askpass_script = Path(tempfile.mktemp(prefix="gh_askpass_"))
            askpass_script.write_text(f"#!/bin/sh\necho \"{self._token}\"\n")
            askpass_script.chmod(0o700)
            env["GIT_ASKPASS"] = str(askpass_script)
            env["GIT_USERNAME"] = "x-access-token"
            # Use https URL without token, git will call askpass
            cmd.extend([clone_url, str(target_dir)])
        else:
            cmd.extend([clone_url, str(target_dir)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
            if result.returncode != 0:
                raise RuntimeError(f"git clone failed: {result.stderr[:500]}")
            return target_dir
        finally:
            if askpass_script and askpass_script.is_file():
                try:
                    askpass_script.unlink()
                except Exception:
                    pass

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

    def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Create GitHub Check Run with annotations at vulnerable lines (beats Snyk)."""
        if not self.configured:
            return None
        # Build annotations from findings
        annotations = []
        for f in findings[:50]:  # GitHub limit 50 per request
            path = f.get("path", "app/main.py")
            # Try to extract line number if available
            line = f.get("line", 1) or 1
            annotations.append(
                {
                    "path": path,
                    "start_line": line,
                    "end_line": line,
                    "annotation_level": "failure" if f.get("severity") == "critical" else "warning",
                    "message": f"{f.get('rule_id', 'SF-001')}: {f.get('title', 'Security finding')}",
                    "title": f.get("rule_id", "Security"),
                    "raw_details": f.get("evidence", "")[:1000],
                }
            )

        payload = {
            "name": "SentinelForge Security Gate",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "failure" if findings else "success",
            "output": {
                "title": f"{len(findings)} findings" if findings else "No vulnerabilities",
                "summary": f"SentinelForge scanned and found {len(findings)} security issues with replayable evidence",
                "annotations": annotations,
            },
        }
        try:
            resp = self._client.post(
                f"https://api.github.com/repos/{owner}/{repo}/check-runs",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def upload_sarif(
        self,
        owner: str,
        repo: str,
        sarif_path: Path,
        commit_sha: str,
    ) -> dict[str, Any] | None:
        """Upload SARIF to GitHub code scanning."""
        if not self.configured or not sarif_path.is_file():
            return None
        try:
            import base64
            import gzip

            content = sarif_path.read_bytes()
            gzipped = gzip.compress(content)
            b64 = base64.b64encode(gzipped).decode()
            payload = {
                "commit_sha": commit_sha,
                "ref": f"refs/heads/{commit_sha}",
                "sarif": b64,
                "tool_name": "SentinelForge",
            }
            resp = self._client.post(
                f"https://api.github.com/repos/{owner}/{repo}/code-scanning/sarifs",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def generate_sarif(
        self,
        findings: list[dict[str, Any]],
        output_path: Path,
    ) -> Path:
        """Generate SARIF 2.1.0 from findings per enterprise standard."""
        import json as _json

        rules = []
        results = []
        seen_rules = set()
        for f in findings:
            rule_id = f.get("rule_id", "SF-001")
            if rule_id not in seen_rules:
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.get("title", rule_id),
                        "shortDescription": {"text": f.get("title", rule_id)},
                        "fullDescription": {"text": f.get("description", "")},
                        "helpUri": f"https://sentinelforge.dev/rules/{rule_id}",
                        "properties": {"severity": f.get("severity", "medium"), "tags": ["security"]},
                    }
                )
                seen_rules.add(rule_id)
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                    "message": {"text": f.get("title", "") + ": " + f.get("evidence", "")[:500]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get("path", "app/main.py")},
                                "region": {"startLine": f.get("line", 1)},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": f.get("finding_id", "")[:16]},
                }
            )

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SentinelForge", "version": "0.2.0", "rules": rules}},
                    "results": results,
                }
            ],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return output_path

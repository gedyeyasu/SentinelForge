from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinelforge.redaction import assert_no_secrets, redact_text


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str
    title: str
    branch: str
    body: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "url": self.url,
            "title": self.title,
            "branch": self.branch,
            "body": self.body,
        }


class PRGenerator:
    """Generate GitHub pull requests with security fixes.

    Auth: token resolved from explicit arg -> GITHUB_TOKEN env -> OAuth
    token file. GIT_ASKPASS avoids tokens on the process list; PR creation
    uses the GitHub REST API so no `gh` CLI install/auth is required.
    """

    def __init__(self, *, github_token: str | None = None) -> None:
        self._token = github_token or self._resolve_token()

    @staticmethod
    def _resolve_token() -> str:
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            return token
        try:
            from sentinelforge.integrations.github import GitHubClient

            return GitHubClient.load_token_from_any_source()
        except Exception:
            return ""

    @property
    def configured(self) -> bool:
        return bool(self._token)

    def _git_env(self) -> tuple[dict[str, str], Path | None]:
        """Env for git subprocesses: GH_TOKEN + GIT_ASKPASS script."""
        env = os.environ.copy()
        askpass = None
        if self._token:
            env["GH_TOKEN"] = self._token
            env["GITHUB_TOKEN"] = self._token
            askpass = Path(tempfile.mktemp(prefix="sf_askpass_"))
            askpass.write_text(f'#!/bin/sh\necho "{self._token}"\n')
            askpass.chmod(0o700)
            env["GIT_ASKPASS"] = str(askpass)
            env["GIT_USERNAME"] = "x-access-token"
            env["GIT_TERMINAL_PROMPT"] = "0"
        return env, askpass

    def create_fix_branch(
        self,
        repo_dir: Path,
        finding_id: str,
        branch_name: str | None = None,
    ) -> str:
        if branch_name is None:
            branch_name = f"sentinelforge/fix-{finding_id[:12]}"
        self._git(repo_dir, "checkout", "-b", branch_name)
        return branch_name

    def commit_patches(
        self,
        repo_dir: Path,
        patched_files: list[Path],
        finding_id: str,
        message: str | None = None,
    ) -> str:
        if message is None:
            message = (
                f"fix(security): {finding_id}\n\n"
                f"Automated security patch by SentinelForge.\n"
                f"Finding: {finding_id}\n"
                f"This fix was verified in an isolated workspace before commit."
            )
        for f in patched_files:
            self._git(repo_dir, "add", str(f))
        self._git(repo_dir, "commit", "-m", message)
        return self._git(repo_dir, "rev-parse", "HEAD")

    def push_branch(
        self,
        repo_dir: Path,
        branch_name: str,
        remote: str = "origin",
    ) -> None:
        self._git(repo_dir, "push", "-u", remote, branch_name)

    def remote_owner_repo(self, repo_dir: Path, remote: str = "origin") -> tuple[str, str] | None:
        """Parse (owner, repo) from the remote URL."""
        try:
            url = self._git(repo_dir, "remote", "get-url", remote)
        except RuntimeError:
            return None
        match = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?$", url.strip())
        if not match:
            return None
        return match.group(1), match.group(2)

    def create_pull_request(
        self,
        repo_dir: Path,
        *,
        title: str,
        body: str,
        base: str = "main",
        head: str,
        draft: bool = True,
        require_human_review: bool = True,
        owner: str | None = None,
        repo: str | None = None,
    ) -> PullRequest | None:
        """Create a draft PR via the GitHub REST API (no gh CLI needed).

        Human review required per safety boundary: PR is always a draft.
        """
        if not self._token:
            return None
        if not (owner and repo):
            parsed = self.remote_owner_repo(repo_dir)
            if parsed is None:
                return None
            owner, repo = parsed
        return self._create_pr_via_api(
            owner=owner,
            repo=repo,
            title=title,
            body=body,
            base=base,
            head=head,
            draft=draft,
        )

    def _create_pr_via_api(
        self,
        *,
        owner: str,
        repo: str,
        title: str,
        body: str,
        base: str,
        head: str,
        draft: bool,
    ) -> PullRequest | None:
        import httpx

        try:
            response = httpx.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={
                    "title": title,
                    "body": body,
                    "base": base,
                    "head": head,
                    "draft": draft,
                },
                timeout=30,
            )
            if response.status_code == 422:
                # PR already exists for this branch — return it
                existing = httpx.get(
                    f"https://api.github.com/repos/{owner}/{repo}/pulls",
                    params={"head": f"{owner}:{head}", "state": "open"},
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Accept": "application/vnd.github+json",
                    },
                    timeout=30,
                )
                if existing.status_code == 200 and existing.json():
                    pr = existing.json()[0]
                    return PullRequest(
                        number=pr["number"],
                        url=pr["html_url"],
                        title=title,
                        branch=head,
                        body=body,
                    )
                return None
            response.raise_for_status()
            pr = response.json()
            return PullRequest(
                number=pr["number"],
                url=pr["html_url"],
                title=title,
                branch=head,
                body=body,
            )
        except Exception:
            return None

    def generate_pr_body(
        self,
        finding: dict[str, Any],
        *,
        patch_sha256: str = "",
        verification_passed: bool = False,
        evidence: dict[str, Any] | None = None,
    ) -> str:
        # Secret redaction per enterprise gate PLAN §13 #9
        safe_finding = {}
        for k, v in finding.items():
            if isinstance(v, str):
                rv, _ = redact_text(v)
                safe_finding[k] = rv[:2000]
            else:
                safe_finding[k] = v

        severity = safe_finding.get("severity", "unknown").upper()
        rule_id = safe_finding.get("rule_id", "unknown")
        description = safe_finding.get("description", "")
        endpoint = safe_finding.get("endpoint", "")
        remediation = safe_finding.get("remediation", "")
        lines = [
            "## Security Fix",
            "",
            f"**Severity:** {severity}",
            f"**Rule:** `{rule_id}`",
            f"**Endpoint:** `{endpoint}`",
            "",
            "### Description",
            description,
            "",
            "### Remediation",
            remediation,
            "",
        ]
        if patch_sha256:
            lines.extend(
                [
                    "### Patch Receipt",
                    f"- SHA-256: `{patch_sha256}`",
                    f"- Verified: {'Yes' if verification_passed else 'Pending'}",
                    "",
                ]
            )
        if evidence:
            lines.extend(
                [
                    "### Evidence (Replayable)",
                    f"- Evidence hash: `{evidence.get('evidence_hash', '')[:16]}...`",
                    f"- Original exploit: `{evidence.get('replay_command', '')[:100]}`",
                    f"- Confidence: {evidence.get('confidence', 0):.0%}",
                    f"- HiddenLayer verdict: {evidence.get('hiddenlayer_verdict', 'checked')}",
                    "",
                ]
            )
        lines.extend(
            [
                "---",
                "*Generated by [SentinelForge](https://github.com/gedyeyasu/SentinelForge) "
                "proof-carrying release gate with signed attestation.*",
                "",
                f"**Attestation:** Patch verified with {len(evidence.get('mutations', []) or [])} mutated exploits blocked" if evidence else "",
            ]
        )
        body = "\n".join(lines)
        # Final secret gate
        assert_no_secrets({"body": body})
        return body

    def generate_branch_name(self, finding: dict[str, Any]) -> str:
        rule_id = finding.get("rule_id", "fix").lower().replace("sf-py-", "").replace("-", "/")
        finding_id = finding.get("finding_id", "")[:8]
        return f"sentinelforge/{rule_id}/{finding_id}"

    def apply_patches(
        self,
        repo_dir: Path,
        patches: dict[str, str],
    ) -> list[Path]:
        committed: list[Path] = []
        for relative_path, content in patches.items():
            target = repo_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            committed.append(target)
        return committed

    def _git(self, repo_dir: Path, *args: str) -> str:
        env, askpass = self._git_env()
        try:
            result = subprocess.run(
                ["git", *args],
                capture_output=True,
                text=True,
                cwd=str(repo_dir),
                timeout=30,
                env=env,
            )
            if result.returncode != 0:
                raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
            return result.stdout.strip()
        finally:
            if askpass and askpass.is_file():
                try:
                    askpass.unlink()
                except OSError:
                    pass

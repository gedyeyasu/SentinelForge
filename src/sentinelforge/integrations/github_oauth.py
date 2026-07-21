from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


@dataclass
class OAuthConfig:
    client_id: str = ""
    client_secret: str = ""
    callback_url: str = "http://localhost:8741/api/github/oauth/callback"
    scope: str = "repo,read:org,read:user"

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


@dataclass
class OAuthState:
    state: str
    created_at: float
    redirect_after: str = "/"


@dataclass
class GitHubToken:
    access_token: str
    token_type: str = "bearer"
    scope: str = ""
    obtained_at: float = 0
    login: str | None = None
    name: str | None = None

    def is_expired(self) -> bool:
        # GitHub OAuth tokens don't expire unless revoked, but we can check age for rotation
        return False

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "login": self.login,
            "name": self.name,
            "scope": self.scope,
            "token_type": self.token_type,
            "obtained_at": self.obtained_at,
            "has_token": bool(self.access_token),
        }


class GitHubOAuthManager:
    """
    Enterprise GitHub OAuth integration for SentinelForge.

    Flow:
    1. Frontend calls GET /api/github/oauth/start -> returns authorize_url + state
    2. User is redirected to https://github.com/login/oauth/authorize?client_id=...&scope=repo,read:org&state=...
    3. GitHub redirects to callback_url?code=xxx&state=yyy
    4. Backend exchanges code for access_token via POST https://github.com/login/oauth/access_token
    5. Token stored securely in .sentinelforge/github_token.json with 600 permissions
    6. GitHubClient loads token from: env GITHUB_TOKEN -> oauth file -> memory

    Security:
    - State parameter prevents CSRF
    - Token file has 600 permissions
    - Token never returned in full via API, only safe dict with has_token flag
    - Secure storage via GIT_ASKPASS not URL embedding (already fixed in github.py)
    """

    def __init__(
        self,
        config: OAuthConfig | None = None,
        storage_dir: Path = Path(".sentinelforge"),
        client: httpx.Client | None = None,
    ) -> None:
        if config:
            self.config = config
        else:
            self.config = OAuthConfig(
                client_id=os.environ.get("GITHUB_CLIENT_ID", "").strip(),
                client_secret=os.environ.get("GITHUB_CLIENT_SECRET", "").strip(),
                callback_url=os.environ.get(
                    "GITHUB_OAUTH_CALLBACK_URL", "http://localhost:8741/api/github/oauth/callback"
                ).strip(),
                scope=os.environ.get("GITHUB_OAUTH_SCOPE", "repo,read:org,read:user").strip(),
            )
        self.storage_dir = storage_dir.resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.token_file = self.storage_dir / "github_token.json"
        self.state_file = self.storage_dir / "github_oauth_state.json"
        self._client = client or httpx.Client(timeout=15, follow_redirects=False)
        self._states: dict[str, OAuthState] = self._load_states()

    def _load_states(self) -> dict[str, OAuthState]:
        if not self.state_file.is_file():
            return {}
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            states = {}
            for s, payload in data.items():
                states[s] = OAuthState(
                    state=payload.get("state", s),
                    created_at=payload.get("created_at", time.time()),
                    redirect_after=payload.get("redirect_after", "/"),
                )
            # Clean expired (10 min)
            now = time.time()
            states = {k: v for k, v in states.items() if now - v.created_at < 600}
            return states
        except Exception:
            return {}

    def _save_states(self) -> None:
        try:
            data = {
                k: {"state": v.state, "created_at": v.created_at, "redirect_after": v.redirect_after}
                for k, v in self._states.items()
            }
            self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.state_file.chmod(0o600)
        except Exception:
            pass

    def get_oauth_config_status(self) -> dict[str, Any]:
        return {
            "configured": self.config.configured,
            "client_id": self.config.client_id[:10] + "..." if self.config.client_id else "",
            "has_client_secret": bool(self.config.client_secret),
            "callback_url": self.config.callback_url,
            "scope": self.config.scope,
            "has_token": self.token_file.is_file(),
            "token_file": str(self.token_file),
        }

    def create_authorize_url(self, redirect_after: str = "/") -> tuple[str, str]:
        """
        Create GitHub OAuth authorize URL with state parameter.
        Returns (authorize_url, state)
        """
        if not self.config.configured:
            raise ValueError("GitHub OAuth not configured: set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env")

        state = secrets.token_urlsafe(32)
        self._states[state] = OAuthState(state=state, created_at=time.time(), redirect_after=redirect_after)
        self._save_states()

        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.callback_url,
            "scope": self.config.scope,
            "state": state,
            "allow_signup": "false",
        }
        from urllib.parse import urlencode

        query_str = urlencode(params)
        authorize_url = f"https://github.com/login/oauth/authorize?{query_str}"
        return authorize_url, state

    def exchange_code_for_token(self, code: str, state: str) -> GitHubToken:
        """
        Exchange OAuth code for access token.
        Validates state for CSRF protection.
        """
        if state not in self._states:
            raise ValueError("Invalid or expired OAuth state - possible CSRF")

        # Clean state after use
        del self._states[state]
        self._save_states()

        if not code:
            raise ValueError("No code provided from GitHub callback")

        if not self.config.configured:
            raise ValueError("GitHub OAuth not configured")

        # Exchange code for token per GitHub docs: POST https://github.com/login/oauth/access_token
        response = self._client.post(
            "https://github.com/login/oauth/access_token",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "code": code,
                "redirect_uri": self.config.callback_url,
            },
        )
        response.raise_for_status()
        data = response.json()

        if "error" in data:
            raise ValueError(f"GitHub OAuth error: {data.get('error_description', data.get('error'))}")

        access_token = data.get("access_token")
        if not access_token:
            raise ValueError(f"No access_token in GitHub response: {data}")

        token = GitHubToken(
            access_token=access_token,
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope", ""),
            obtained_at=time.time(),
        )

        # Try to fetch user info to store login
        try:
            user_resp = self._client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                token.login = user_data.get("login")
                token.name = user_data.get("name")
        except Exception:
            pass

        self._store_token(token)
        return token

    def _store_token(self, token: GitHubToken) -> None:
        try:
            data = {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "scope": token.scope,
                "obtained_at": token.obtained_at,
                "login": token.login,
                "name": token.name,
            }
            self.token_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.token_file.chmod(0o600)
        except Exception as e:
            raise RuntimeError(f"Failed to store GitHub token securely: {e}") from e

    def load_token(self) -> GitHubToken | None:
        # Try env first (explicit takes precedence)
        env_token = os.environ.get("GITHUB_TOKEN", "").strip()
        if env_token:
            return GitHubToken(
                access_token=env_token,
                obtained_at=time.time(),
                scope="env",
            )

        # Then oauth file
        if not self.token_file.is_file():
            return None

        try:
            data = json.loads(self.token_file.read_text(encoding="utf-8"))
            return GitHubToken(
                access_token=data.get("access_token", ""),
                token_type=data.get("token_type", "bearer"),
                scope=data.get("scope", ""),
                obtained_at=data.get("obtained_at", 0),
                login=data.get("login"),
                name=data.get("name"),
            )
        except Exception:
            return None

    def delete_token(self) -> bool:
        if self.token_file.is_file():
            self.token_file.unlink()
            return True
        return False

    def get_status(self) -> dict[str, Any]:
        token = self.load_token()
        oauth_status = self.get_oauth_config_status()

        if token:
            return {
                "status": "authenticated",
                "source": "oauth_file" if self.token_file.is_file() else "env",
                "login": token.login,
                "name": token.name,
                "scope": token.scope,
                "has_token": True,
                "oauth_configured": oauth_status["configured"],
            }
        else:
            return {
                "status": "not_configured",
                "message": "Set GITHUB_TOKEN env or connect via OAuth at /api/github/oauth/start",
                "has_token": False,
                "oauth_configured": oauth_status["configured"],
                "oauth": oauth_status,
            }

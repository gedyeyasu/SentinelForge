from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from sentinelforge.event_bus import EventBus, LiveEvent
from sentinelforge.scope import ScopeConfig, TestIdentity

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProvisionedAccount:
    role: str
    email: str
    user_id: str
    access_token: str
    refresh_token: str
    method: str  # "registered" | "login"


class IdentityProvisioner:
    """Provisions synthetic test identities on the target at run start.

    Instead of static JWTs in env vars (which expire), the agent creates
    two run-scoped accounts on the target's public registration endpoint —
    exactly what any anonymous user can do — and uses their tokens for
    cross-tenant (BOLA) testing.

    Safety properties:
    - Emails are run-scoped and use the reserved .invalid TLD:
      sf-<run>-<role>@sentinelforge-test.invalid (never a real mailbox)
    - Falls back to login if the account already exists
    - Falls back to scope-configured static identities if provisioning
      fails entirely (never blocks a run)
    - Emits SSE events so provisioning is visible in the live feed
    """

    AGENT_ROLE = "identity_provisioner"

    def __init__(
        self,
        scope: ScopeConfig,
        *,
        run_id: str,
        bus: EventBus | None = None,
        phase: str = "scoping",
        timeout_seconds: float = 15,
        http_post: Any | None = None,
    ) -> None:
        self._scope = scope
        self._run_id = run_id
        self._bus = bus
        self._phase = phase
        self._timeout = timeout_seconds
        # Injectable for tests; defaults to httpx
        self._http_post = http_post

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self._bus is None:
            return
        self._bus.publish(
            LiveEvent(
                run_id=self._run_id,
                phase=self._phase,
                kind=kind,
                timestamp=time.time(),
                payload=payload,
            )
        )

    def _post(self, url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if self._http_post is not None:
            return self._http_post(url, payload)
        import httpx

        response = httpx.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
        )
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body

    def provision(self) -> tuple[ScopeConfig, list[ProvisionedAccount]]:
        """Create/obtain owner+attacker identities; return updated scope.

        Never raises: on total failure returns the original scope so the
        run proceeds with static identities (if any).
        """
        base = self._scope.target.base_url.rstrip("/")
        run_tag = self._run_id.replace("sf_pentest_", "")[:10]
        accounts: list[ProvisionedAccount] = []

        self._emit(
            "identities_provisioning",
            {
                "agent": self.AGENT_ROLE,
                "message": (
                    "Provisioning synthetic test identities on target "
                    "(run-scoped accounts via public registration)"
                ),
            },
        )

        for role in ("owner", "attacker"):
            email = f"sf-{run_tag}-{role}@sentinelforge-test.invalid"
            password = f"Sf!{secrets.token_urlsafe(18)}aA1"
            account = self._register_or_login(base, role, email, password)
            if account is None:
                self._emit(
                    "identities_provision_failed",
                    {
                        "agent": self.AGENT_ROLE,
                        "message": (
                            f"Identity provisioning failed for {role}; "
                            "falling back to scope-configured identities"
                        ),
                        "role": role,
                    },
                )
                return self._scope, accounts
            accounts.append(account)
            self._emit(
                "identity_provisioned",
                {
                    "agent": self.AGENT_ROLE,
                    "message": (
                        f"{role} identity ready: {email} "
                        f"({account.method}, user {account.user_id})"
                    ),
                    "role": role,
                    "email": email,
                    "method": account.method,
                    "user_id": account.user_id,
                },
            )

        identities = (
            TestIdentity(
                name="owner",
                tenant_id="tenant-a",
                headers={
                    "Authorization": f"Bearer {accounts[0].access_token}",
                    "x-user-id": accounts[0].user_id,
                },
            ),
            TestIdentity(
                name="attacker",
                tenant_id="tenant-b",
                headers={
                    "Authorization": f"Bearer {accounts[1].access_token}",
                    "x-user-id": accounts[1].user_id,
                },
            ),
        )
        return self._scope.with_identities(identities), accounts

    def _register_or_login(
        self, base: str, role: str, email: str, password: str
    ) -> ProvisionedAccount | None:
        register_url = f"{base}/auth/email/register/"
        login_url = f"{base}/auth/email/login/"

        try:
            status, body = self._post(
                register_url,
                {
                    "email": email,
                    "password": password,
                    "name": f"SentinelForge Test ({role})",
                },
            )
            if status in (200, 201) and body.get("access"):
                return self._account_from_body(role, email, body, "registered")
            # Duplicate email or other 400 -> try login
            if status in (400, 409):
                logger.info(
                    "Registration for %s returned %s, trying login",
                    email, status,
                )
            elif status == 403:
                logger.warning(
                    "Email registration disabled on target (%s)", status
                )
        except Exception as error:
            logger.warning("Registration request failed: %s", error)

        try:
            status, body = self._post(
                login_url, {"email": email, "password": password}
            )
            if status == 200 and body.get("access"):
                return self._account_from_body(role, email, body, "login")
            logger.warning(
                "Login for %s failed: %s %s", email, status, str(body)[:200]
            )
        except Exception as error:
            logger.warning("Login request failed: %s", error)
        return None

    @staticmethod
    def _account_from_body(
        role: str, email: str, body: dict[str, Any], method: str
    ) -> ProvisionedAccount:
        user = body.get("user", {}) if isinstance(body.get("user"), dict) else {}
        return ProvisionedAccount(
            role=role,
            email=email,
            user_id=str(user.get("id", "unknown")),
            access_token=str(body["access"]),
            refresh_token=str(body.get("refresh", "")),
            method=method,
        )


def serialize_accounts(accounts: list[ProvisionedAccount]) -> list[dict[str, Any]]:
    """Safe serialization for state/DB — never includes tokens."""
    return [
        {
            "role": a.role,
            "email": a.email,
            "user_id": a.user_id,
            "method": a.method,
        }
        for a in accounts
    ]

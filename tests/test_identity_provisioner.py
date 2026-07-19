from __future__ import annotations

from sentinelforge.identity import IdentityProvisioner
from sentinelforge.identity.provisioner import serialize_accounts
from sentinelforge.scope import ScopeConfig, TargetConfig, TestIdentity


def _scope() -> ScopeConfig:
    return ScopeConfig(
        target=TargetConfig(base_url="https://api.cini.love/api/v1"),
        allowed_hosts=("api.cini.love",),
        provision_identities=True,
        test_identities=(
            TestIdentity(
                name="owner",
                tenant_id="tenant-a",
                headers={"Authorization": "Bearer static-fallback"},
            ),
        ),
    )


def _ok_response(url: str, payload: dict) -> tuple[int, dict]:
    role = "owner" if "owner" in payload["email"] else "attacker"
    return 200, {
        "access": f"access-token-{role}",
        "refresh": f"refresh-token-{role}",
        "user": {"id": f"user-{role}-123", "email": payload["email"]},
        "is_new_user": True,
    }


def test_provision_registers_both_identities() -> None:
    provisioner = IdentityProvisioner(
        _scope(), run_id="sf_pentest_abc1234567", http_post=_ok_response
    )
    scope, accounts = provisioner.provision()
    assert len(accounts) == 2
    assert accounts[0].method == "registered"
    assert accounts[0].email.startswith("sf-abc1234567-owner@")
    assert accounts[0].email.endswith("@sentinelforge-test.invalid")

    identities = scope.test_identities
    assert len(identities) == 2
    owner, attacker = identities
    assert owner.headers["Authorization"] == "Bearer access-token-owner"
    assert attacker.headers["Authorization"] == "Bearer access-token-attacker"
    assert owner.headers["x-user-id"] == "user-owner-123"
    # Provisioning flag consumed so repeat phases don't re-provision
    assert scope.provision_identities is False


def test_provision_falls_back_to_login_on_duplicate() -> None:
    def _fake(url: str, payload: dict) -> tuple[int, dict]:
        if "register" in url:
            return 400, {"email": ["A user with this email already exists."]}
        return 200, {
            "access": "login-access",
            "refresh": "login-refresh",
            "user": {"id": "existing-user-9"},
        }

    provisioner = IdentityProvisioner(
        _scope(), run_id="sf_pentest_abc1234567", http_post=_fake
    )
    scope, accounts = provisioner.provision()
    assert len(accounts) == 2
    assert accounts[0].method == "login"
    assert scope.test_identities[0].headers["Authorization"] == (
        "Bearer login-access"
    )


def test_provision_failure_returns_original_scope() -> None:
    def _failing(url: str, payload: dict) -> tuple[int, dict]:
        return 500, {}

    original = _scope()
    provisioner = IdentityProvisioner(
        original, run_id="sf_pentest_abc1234567", http_post=_failing
    )
    scope, accounts = provisioner.provision()
    assert accounts == []
    assert scope is original
    assert scope.test_identities[0].headers["Authorization"] == (
        "Bearer static-fallback"
    )


def test_serialize_accounts_never_includes_tokens() -> None:
    provisioner = IdentityProvisioner(
        _scope(), run_id="sf_pentest_abc1234567", http_post=_ok_response
    )
    _, accounts = provisioner.provision()
    serialized = serialize_accounts(accounts)
    assert serialized[0]["email"].startswith("sf-")
    assert serialized[0]["method"] == "registered"
    assert "access" not in serialized[0]
    assert "access_token" not in serialized[0]
    assert "refresh" not in serialized[0]


def test_password_satisfies_strength_requirements() -> None:
    captured: list[dict] = []

    def _capture(url: str, payload: dict) -> tuple[int, dict]:
        captured.append(payload)
        return _ok_response(url, payload)

    provisioner = IdentityProvisioner(
        _scope(), run_id="sf_pentest_abc1234567", http_post=_capture
    )
    provisioner.provision()
    password = captured[0]["password"]
    assert len(password) >= 8
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)

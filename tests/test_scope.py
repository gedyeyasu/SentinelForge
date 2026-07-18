from pathlib import Path

import pytest
import yaml

from sentinelforge.scope import (
    ScopeConfig,
    ScopeValidationError,
    TargetConfig,
    TestIdentity,
    load_scope,
    scope_matches_host,
)


def _write_scope(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


FULL_SCOPE = {
    "target": {
        "base_url": "http://127.0.0.1:8000",
        "ownership_verified": True,
    },
    "allowed_hosts": ["127.0.0.1", "localhost"],
    "allowed_methods": ["GET", "POST", "PUT", "PATCH"],
    "forbidden_paths": ["/admin"],
    "max_requests_per_second": 5,
    "max_total_requests": 100,
    "allow_destructive_payloads": False,
    "allow_denial_of_service": False,
    "allow_persistence": False,
    "allow_data_exfiltration": False,
    "test_identities": [
        {
            "name": "owner",
            "tenant_id": "tenant-a",
            "headers": {"x-user-id": "tenant-a-user"},
        },
        {
            "name": "attacker",
            "tenant_id": "tenant-b",
            "headers": {"x-user-id": "tenant-b-user"},
        },
    ],
    "kill_switch_file": "/tmp/sf-stop",
}


def test_load_scope_full(tmp_path: Path) -> None:
    path = _write_scope(tmp_path, FULL_SCOPE)
    scope = load_scope(path)

    assert scope.target.base_url == "http://127.0.0.1:8000"
    assert scope.target.ownership_verified is True
    assert scope.allowed_hosts == ("127.0.0.1", "localhost")
    assert scope.allowed_methods == ("GET", "POST", "PUT", "PATCH")
    assert scope.forbidden_paths == ("/admin",)
    assert scope.max_requests_per_second == 5
    assert scope.max_total_requests == 100
    assert len(scope.test_identities) == 2
    assert scope.test_identities[0].name == "owner"
    assert scope.test_identities[1].tenant_id == "tenant-b"
    assert scope.kill_switch_file == "/tmp/sf-stop"


def test_load_scope_defaults(tmp_path: Path) -> None:
    minimal = {
        "target": {"base_url": "http://localhost:3000"},
        "allowed_hosts": ["localhost"],
        "test_identities": [],
    }
    path = _write_scope(tmp_path, minimal)
    scope = load_scope(path)

    assert scope.max_requests_per_second == 3
    assert scope.max_total_requests == 300
    assert scope.allow_destructive_payloads is False
    assert scope.test_identities == ()


def test_load_scope_missing_target(tmp_path: Path) -> None:
    path = _write_scope(tmp_path, {"allowed_hosts": ["localhost"]})
    with pytest.raises(ScopeValidationError, match="scope.target is required"):
        load_scope(path)


def test_load_scope_missing_hosts(tmp_path: Path) -> None:
    path = _write_scope(tmp_path, {"target": {"base_url": "http://localhost"}})
    with pytest.raises(ScopeValidationError, match="scope.allowed_hosts"):
        load_scope(path)


def test_load_scope_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "scope.yaml"
    path.write_text(":\n  - :\n    invalid: [", encoding="utf-8")
    with pytest.raises(ScopeValidationError, match="Invalid YAML"):
        load_scope(path)


def test_load_scope_nonexistent_file() -> None:
    with pytest.raises(ScopeValidationError, match="not found"):
        load_scope(Path("/nonexistent/scope.yaml"))


def test_load_scope_empty_identity(tmp_path: Path) -> None:
    data = {
        "target": {"base_url": "http://localhost"},
        "allowed_hosts": ["localhost"],
        "test_identities": [{"name": "", "tenant_id": "a"}],
    }
    path = _write_scope(tmp_path, data)
    with pytest.raises(ScopeValidationError, match="test_identities"):
        load_scope(path)


def test_scope_matches_host_exact() -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://localhost"),
        allowed_hosts=("localhost", "127.0.0.1"),
    )
    assert scope_matches_host(scope, "localhost") is True
    assert scope_matches_host(scope, "127.0.0.1") is True
    assert scope_matches_host(scope, "evil.com") is False


def test_scope_matches_host_wildcard() -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://staging.example.com"),
        allowed_hosts=("*.example.com",),
    )
    assert scope_matches_host(scope, "staging.example.com") is True
    assert scope_matches_host(scope, "api.example.com") is True
    assert scope_matches_host(scope, "evil.com") is False


def test_scope_matches_host_case_insensitive() -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://localhost"),
        allowed_hosts=("LocalHost",),
    )
    assert scope_matches_host(scope, "localhost") is True
    assert scope_matches_host(scope, "LOCALHOST") is True


def test_test_identity_auth_header() -> None:
    identity = TestIdentity(
        name="owner",
        tenant_id="tenant-a",
        headers={"x-user-id": "tenant-a-user"},
    )
    assert identity.auth_header() == {"x-user-id": "tenant-a-user"}


def test_scope_config_identity_names() -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://localhost"),
        allowed_hosts=("localhost",),
        test_identities=(
            TestIdentity(name="a", tenant_id="t1"),
            TestIdentity(name="b", tenant_id="t2"),
        ),
    )
    assert scope.identity_names() == ("a", "b")


def test_scope_config_get_identity() -> None:
    identity = TestIdentity(name="owner", tenant_id="t1")
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://localhost"),
        allowed_hosts=("localhost",),
        test_identities=(identity,),
    )
    assert scope.get_identity("owner") is identity
    assert scope.get_identity("missing") is None

from pathlib import Path

import yaml

from sentinelforge.policy import DenialReason, PolicyEngine, PolicyVerdict
from sentinelforge.scope import (
    ScopeConfig,
    TargetConfig,
    load_scope,
)


def _write_scope(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


def _make_scope(tmp_path: Path, **overrides: object) -> ScopeConfig:
    data = {
        "target": {"base_url": "http://127.0.0.1:8000"},
        "allowed_hosts": ["127.0.0.1", "localhost"],
        "allowed_methods": ["GET", "POST", "PUT", "PATCH"],
        "forbidden_paths": ["/admin"],
        "max_requests_per_second": 3,
        "max_total_requests": 10,
        "test_identities": [
            {"name": "owner", "tenant_id": "t1", "headers": {"x-user-id": "a"}},
            {"name": "attacker", "tenant_id": "t2", "headers": {"x-user-id": "b"}},
        ],
        "kill_switch_file": str(tmp_path / "STOP"),
    }
    data.update(overrides)
    path = _write_scope(tmp_path, data)
    return load_scope(path)


def test_policy_allows_in_scope_request(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://127.0.0.1:8000/orders/1")
    assert decision.allowed is True
    assert decision.verdict is PolicyVerdict.ALLOWED


def test_policy_blocks_out_of_scope_host(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://evil.com/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.OUT_OF_SCOPE_HOST


def test_policy_blocks_forbidden_method(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("DELETE", "http://127.0.0.1:8000/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.FORBIDDEN_METHOD


def test_policy_blocks_forbidden_path(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://127.0.0.1:8000/admin/secret")
    assert decision.allowed is False
    assert decision.reason is DenialReason.FORBIDDEN_PATH


def test_policy_blocks_private_address_not_in_scope(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://192.168.1.1/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.PRIVATE_ADDRESS_BLOCKED


def test_policy_allows_localhost_when_in_scope(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://localhost:8000/orders/1")
    assert decision.allowed is True


def test_policy_blocks_destructive_payload_when_not_allowed(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate(
        "POST", "http://127.0.0.1:8000/orders", destructive=True
    )
    assert decision.allowed is False
    assert decision.reason is DenialReason.DESTRUCTIVE_PAYLOAD_BLOCKED


def test_policy_allows_destructive_payload_when_allowed(tmp_path: Path) -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        allowed_hosts=("127.0.0.1",),
        allow_destructive_payloads=True,
    )
    engine = PolicyEngine(scope)

    decision = engine.evaluate(
        "POST", "http://127.0.0.1:8000/orders", destructive=True
    )
    assert decision.allowed is True


def test_policy_blocks_dos_when_not_allowed(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    decision = engine.evaluate("GET", "http://127.0.0.1:8000/orders/1", dos_like=True)
    assert decision.allowed is False
    assert decision.reason is DenialReason.DOS_BLOCKED


def test_policy_enforces_rate_limit(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path, max_requests_per_second=2)
    engine = PolicyEngine(scope)

    assert engine.evaluate("GET", "http://127.0.0.1:8000/a").allowed is True
    engine.record_request()
    assert engine.evaluate("GET", "http://127.0.0.1:8000/b").allowed is True
    engine.record_request()
    decision = engine.evaluate("GET", "http://127.0.0.1:8000/c")
    assert decision.allowed is False
    assert decision.reason is DenialReason.RATE_LIMIT_EXCEEDED


def test_policy_enforces_total_request_limit(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path, max_total_requests=3)
    engine = PolicyEngine(scope)

    for _ in range(3):
        engine.record_request()
    decision = engine.evaluate("GET", "http://127.0.0.1:8000/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.REQUEST_LIMIT_EXCEEDED


def test_policy_kill_switch_file(tmp_path: Path) -> None:
    stop_file = tmp_path / "STOP"
    scope = _make_scope(tmp_path, kill_switch_file=str(stop_file))
    engine = PolicyEngine(scope)

    assert engine.evaluate("GET", "http://127.0.0.1:8000/orders/1").allowed is True

    stop_file.write_text("stop", encoding="utf-8")

    decision = engine.evaluate("GET", "http://127.0.0.1:8000/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.KILL_SWITCH_ACTIVE


def test_policy_kill_switch_in_memory(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path)
    engine = PolicyEngine(scope)

    engine._kill_switch_active = True

    decision = engine.evaluate("GET", "http://127.0.0.1:8000/orders/1")
    assert decision.allowed is False
    assert decision.reason is DenialReason.KILL_SWITCH_ACTIVE


def test_policy_remaining_budget(tmp_path: Path) -> None:
    scope = _make_scope(tmp_path, max_total_requests=10, max_requests_per_second=5)
    engine = PolicyEngine(scope)

    budget = engine.remaining_budget()
    assert budget["requests_remaining"] == 10
    assert budget["per_second_remaining"] == 5

    engine.record_request()
    budget = engine.remaining_budget()
    assert budget["requests_remaining"] == 9


def test_policy_decision_properties() -> None:
    from sentinelforge.policy import PolicyDecision

    assert PolicyDecision.allow().allowed is True
    deny = PolicyDecision.deny(DenialReason.OUT_OF_SCOPE_HOST, "test")
    assert deny.allowed is False
    assert deny.reason is DenialReason.OUT_OF_SCOPE_HOST
    assert deny.detail == "test"

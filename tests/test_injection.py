import httpx

from sentinelforge.agents.http import ScopedHTTPClient
from sentinelforge.agents.injection import (
    INJECTION_PAYLOADS,
    InjectionAttacker,
)
from sentinelforge.policy import PolicyEngine
from sentinelforge.scope import ScopeConfig, TargetConfig, TestIdentity


def _make_scope() -> ScopeConfig:
    return ScopeConfig(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        allowed_hosts=("127.0.0.1",),
        max_requests_per_second=10,
        max_total_requests=100,
        test_identities=(
            TestIdentity(
                name="owner", tenant_id="t1",
                headers={"x-user-id": "a"},
            ),
        ),
    )


def test_injection_attacker_blocks_out_of_scope() -> None:
    scope = _make_scope()
    engine = PolicyEngine(scope)
    client = ScopedHTTPClient(engine)
    attacker = InjectionAttacker(scope, client)

    result = attacker.attack_endpoint("http://evil.com/inject")

    assert result.blocked_count == len(INJECTION_PAYLOADS)
    assert result.allowed_count == 0


def test_injection_attacker_detects_rejection() -> None:
    scope = _make_scope()
    engine = PolicyEngine(scope)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="blocked")

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = ScopedHTTPClient(engine, http_client)
    attacker = InjectionAttacker(scope, client)

    result = attacker.attack_endpoint("http://127.0.0.1:8000/inject")

    assert result.blocked_count == len(INJECTION_PAYLOADS)
    assert result.allowed_count == 0


def test_injection_attacker_detects_accepted_payload() -> None:
    scope = _make_scope()
    engine = PolicyEngine(scope)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='{"status": "ok"}')

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = ScopedHTTPClient(engine, http_client)
    attacker = InjectionAttacker(scope, client)

    result = attacker.attack_endpoint("http://127.0.0.1:8000/inject")

    assert result.allowed_count == len(INJECTION_PAYLOADS)
    assert result.blocked_count == 0


def test_injection_attacker_uses_custom_payloads() -> None:
    scope = _make_scope()
    engine = PolicyEngine(scope)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = ScopedHTTPClient(engine, http_client)
    attacker = InjectionAttacker(scope, client)

    from sentinelforge.agents.injection import InjectionPayload

    custom = (
        InjectionPayload(
            name="test", payload="test",
            category="test", description="test",
        ),
    )
    result = attacker.attack_endpoint(
        "http://127.0.0.1:8000/inject",
        payloads=custom,
    )

    assert result.payloads_tested == 1


def test_injection_receipt_has_replay_command() -> None:
    scope = _make_scope()
    engine = PolicyEngine(scope)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    client = ScopedHTTPClient(engine, http_client)
    attacker = InjectionAttacker(scope, client)

    result = attacker.attack_endpoint("http://127.0.0.1:8000/inject")

    for receipt in result.receipts:
        assert receipt.replay_command.startswith("curl")

from __future__ import annotations

from sentinelforge.agents import ExploitOutcome
from sentinelforge.agents.discovery import DiscoveredRoute
from sentinelforge.intelligence.novel_attack import NovelAttackSynthesizer
from sentinelforge.scope import ScopeConfig, TargetConfig, TestIdentity


def _scope() -> ScopeConfig:
    return ScopeConfig(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        allowed_hosts=("127.0.0.1", "localhost"),
        test_identities=(
            TestIdentity(
                name="owner",
                tenant_id="tenant-a",
                headers={"x-user-id": "1"},
            ),
            TestIdentity(
                name="attacker",
                tenant_id="tenant-b",
                headers={"x-user-id": "2"},
            ),
        ),
    )


def _route() -> DiscoveredRoute:
    return DiscoveredRoute(
        method="GET",
        path="/orders/{order_id}",
        function_name="get_order",
        source_file="app/main.py",
        path_params=("order_id",),
    )


class _FakeResponse:
    def __init__(self, status: int, body: str) -> None:
        self.status_code = status
        self.body = body


class _FakeClient:
    def __init__(self, status: int = 200, body: str = "{}") -> None:
        self.status = status
        self.body = body
        self.requests: list[tuple[str, str]] = []

    def request(self, method, url, *, headers=None, content=None):
        self.requests.append((method, url))
        return _FakeResponse(self.status, self.body)


def test_composition_engine_generates_hypotheses() -> None:
    synth = NovelAttackSynthesizer(_scope(), _FakeClient())
    hypotheses = synth.synthesize([_route()], max_hypotheses=30)
    classes = {h.attack_class for h in hypotheses}
    assert any("id_smuggling" in c for c in classes)
    assert "param_pollution_bola" in classes
    assert "auth_context_smuggling" in classes
    assert all(h.source == "composition_engine" for h in hypotheses)


def test_mass_assignment_generated_for_mutating_routes() -> None:
    route = DiscoveredRoute(
        method="POST",
        path="/users",
        function_name="create_user",
        source_file="app/main.py",
        path_params=(),
    )
    synth = NovelAttackSynthesizer(_scope(), _FakeClient())
    hypotheses = synth.synthesize([route], max_hypotheses=30)
    classes = {h.attack_class for h in hypotheses}
    assert "mass_assignment" in classes
    assert "race_condition" in classes
    assert "type_juggling" in classes


def test_novelty_scoring_deprioritizes_prior_classes() -> None:
    prior = [{"attack_class": "param_pollution_bola"}]
    synth = NovelAttackSynthesizer(
        _scope(), _FakeClient(), prior_attacks=prior
    )
    hypotheses = synth.synthesize([_route()], max_hypotheses=30)
    pollution = [
        h for h in hypotheses
        if h.attack_class == "param_pollution_bola"
    ]
    others = [
        h for h in hypotheses
        if h.attack_class != "param_pollution_bola"
    ]
    if pollution and others:
        assert pollution[0].novelty_score < others[0].novelty_score


def test_execute_produces_receipts() -> None:
    client = _FakeClient(status=200, body='{"id": 1, "tenant": "tenant-a"}')
    synth = NovelAttackSynthesizer(_scope(), client)
    hypotheses = synth.synthesize([_route()], max_hypotheses=2)
    scope = _scope()
    receipts = synth.execute(
        hypotheses[0],
        owner_identity=scope.test_identities[0],
        attacker_identity=scope.test_identities[1],
    )
    assert receipts
    receipt = receipts[0]
    assert receipt.agent_role == "novel_attack_synthesizer"
    assert receipt.outcome is ExploitOutcome.SUCCESS
    assert receipt.evidence_hash
    assert "curl" in receipt.replay_command


def test_execute_marks_blocked_responses() -> None:
    client = _FakeClient(status=404, body='{"detail": "Not found"}')
    synth = NovelAttackSynthesizer(_scope(), client)
    hypotheses = synth.synthesize([_route()], max_hypotheses=1)
    receipts = synth.execute(hypotheses[0])
    assert receipts[0].outcome is ExploitOutcome.BLOCKED


def test_llm_hypothesis_parsing() -> None:
    synth = NovelAttackSynthesizer(_scope(), _FakeClient())
    content = """```json
[
  {
    "title": "JWT alg confusion",
    "rationale": "RS256 to HS256 downgrade may be accepted",
    "attack_class": "jwt_alg_confusion",
    "severity": "critical",
    "target_path": "/orders/{order_id}",
    "steps": [
      {
        "method": "GET",
        "url_suffix": "/orders/1",
        "headers": {"Authorization": "Bearer x"},
        "body": null,
        "success_signal": "cross_tenant_data"
      }
    ]
  }
]
```"""
    hypotheses = synth._parse_llm_hypotheses(content)
    assert len(hypotheses) == 1
    hyp = hypotheses[0]
    assert hyp.source == "llm"
    assert hyp.attack_class == "jwt_alg_confusion"
    assert hyp.novelty_score == 0.9
    assert hyp.steps[0].url == "http://127.0.0.1:8000/orders/1"


def test_llm_parsing_rejects_out_of_scope_urls() -> None:
    scope = ScopeConfig(
        target=TargetConfig(base_url="http://127.0.0.1:8000"),
        allowed_hosts=("127.0.0.1",),
    )
    synth = NovelAttackSynthesizer(scope, _FakeClient())
    synth._base_url = "http://127.0.0.1:8000"
    content = (
        '[{"title": "x", "rationale": "y", "attack_class": "z",'
        ' "severity": "low", "target_path": "/a",'
        ' "steps": [{"method": "GET", "url_suffix": "/a",'
        ' "headers": {}, "body": null, "success_signal": ""}]}]'
    )
    hypotheses = synth._parse_llm_hypotheses(content)
    assert len(hypotheses) == 1  # in-scope suffix accepted

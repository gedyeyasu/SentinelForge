from __future__ import annotations

from sentinelforge.domain import Finding, Severity
from sentinelforge.event_bus import EventBus
from sentinelforge.inference.base import PatchProposal, ProposedFile
from sentinelforge.patchflow import PatchPRAgent


def _finding() -> Finding:
    return Finding(
        finding_id="fastapi-bola-abc123",
        rule_id="fastapi_bola",
        title="BOLA on GET /orders/{order_id}",
        severity=Severity.CRITICAL,
        path="app/main.py",
        line=31,
        function="get_order",
        endpoint="/orders/{order_id}",
        method="GET",
        description="Missing tenant ownership check",
        invariant="Orders must be scoped to the requesting tenant",
        evidence={},
        remediation="Add tenant check",
        confidence=0.95,
    )


class _Proposer:
    last_provider = "nvidia_nim"

    def __init__(self, guarded: bool = True) -> None:
        self._guarded = guarded

    def propose(self, finding, repository_root):
        content = (
            "def get_order(order_id, user):\n"
            "    order = db.get(order_id)\n"
            "    if order.tenant_id != user.tenant_id:\n"
            "        raise HTTPException(status_code=404)\n"
            if self._guarded
            else "def get_order(order_id):\n    return db.get(order_id)\n"
        )
        return PatchProposal(
            finding_id=finding.finding_id,
            provider="nvidia_nim",
            model="nemotron",
            rationale="Add tenant ownership guard",
            files=[ProposedFile(path="app/main.py", content=content)],
            latency_ms=100,
        )


class _FailingProposer:
    last_provider = "none"

    def propose(self, finding, repository_root):
        raise RuntimeError("NIM down and vLLM down")


def test_patch_agent_proposes_and_verifies() -> None:
    bus = EventBus.instance()
    agent = PatchPRAgent(
        run_id="run_test",
        bus=bus,
        proposer=_Proposer(guarded=True),
    )
    result = agent.process_finding(_finding(), create_pr=False)
    assert result.status == "verified"
    assert result.patch_provider == "nvidia_nim"
    assert result.verification["verified"] is True
    assert result.verification["files_with_guard"] == 1


def test_patch_agent_rejects_unguarded_patch() -> None:
    bus = EventBus.instance()
    agent = PatchPRAgent(
        run_id="run_test",
        bus=bus,
        proposer=_Proposer(guarded=False),
    )
    result = agent.process_finding(_finding(), create_pr=False)
    assert result.status == "failed"
    assert "adversarial" in result.error


def test_patch_agent_handles_proposer_failure() -> None:
    bus = EventBus.instance()
    agent = PatchPRAgent(
        run_id="run_test",
        bus=bus,
        proposer=_FailingProposer(),
    )
    result = agent.process_finding(_finding(), create_pr=False)
    assert result.status == "failed"
    assert "NIM down" in result.error


def test_patch_agent_skips_without_proposer() -> None:
    bus = EventBus.instance()
    agent = PatchPRAgent(run_id="run_test", bus=bus, proposer=None)
    result = agent.process_finding(_finding(), create_pr=False)
    assert result.status == "skipped"

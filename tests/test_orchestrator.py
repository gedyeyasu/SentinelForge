import asyncio
from pathlib import Path

from sentinelforge.control.models import PentestRunRequest
from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.orchestrator import AgentOrchestrator, Phase
from sentinelforge.pentest_modes import PentestMode


def _make_store(tmp_path: Path) -> SQLiteRunStore:
    return SQLiteRunStore(tmp_path / "runs.sqlite3")


def test_orchestrator_plan_phases_quick(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    orch = AgentOrchestrator(store, mode=PentestMode.QUICK)
    phases = orch.plan_phases()
    assert Phase.AUTH_ATTACK not in phases
    assert Phase.INJECTION_ATTACK not in phases
    assert Phase.DEPENDENCY_SCAN in phases
    assert Phase.PATTERN_SCAN in phases


def test_orchestrator_plan_phases_standard(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    orch = AgentOrchestrator(store, mode=PentestMode.STANDARD)
    phases = orch.plan_phases()
    assert Phase.AUTH_ATTACK in phases
    assert Phase.INJECTION_ATTACK in phases
    assert Phase.DEPENDENCY_SCAN in phases
    assert Phase.PATTERN_SCAN in phases
    assert Phase.HIDDENLAYER_SCAN in phases


def test_orchestrator_plan_phases_targeted(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    orch = AgentOrchestrator(store, mode=PentestMode.TARGETED)
    phases = orch.plan_phases()
    assert Phase.AUTH_ATTACK in phases
    assert Phase.INJECTION_ATTACK in phases
    assert Phase.DEPENDENCY_SCAN not in phases
    assert Phase.PATTERN_SCAN not in phases
    assert Phase.HIDDENLAYER_SCAN not in phases


def test_orchestrator_register_handler(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    orch = AgentOrchestrator(store, mode=PentestMode.QUICK)

    def handler(
        run_id: str, config: object, state: object
    ) -> dict[str, str]:
        return {"result": "ok"}

    orch.register_handler(Phase.INIT, handler)
    assert Phase.INIT in orch._handlers


def test_orchestrator_execute_with_handler(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    request = PentestRunRequest(
        repository="examples/vulnerable_shop",
        scope_file="config/scope.yaml",
    )
    run_id = "test_run_001"
    store.create_pentest_run(run_id, request)

    orch = AgentOrchestrator(store, mode=PentestMode.QUICK)
    results_log: list[str] = []

    def counting_handler(
        run_id: str, config: object, state: object
    ) -> dict[str, str]:
        results_log.append("called")
        return {"result": "ok"}

    orch.register_handler(Phase.INIT, counting_handler)

    context = {"repository": "test"}
    state = asyncio.run(orch.execute(run_id, context))

    assert "init" in state.phase_results
    assert state.phase_results["init"].success is True
    assert len(results_log) == 1

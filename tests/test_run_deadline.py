from __future__ import annotations

import time
from pathlib import Path

import pytest

from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.orchestrator import (
    AgentOrchestrator,
    Phase,
    RunDeadlineExceeded,
)
from sentinelforge.pentest_modes import PentestMode, get_mode_config


def test_mode_config_has_max_run_seconds_default_1800() -> None:
    for mode in PentestMode:
        config = get_mode_config(mode)
        assert config.max_run_seconds == 1800
        assert config.to_dict()["max_run_seconds"] == 1800


def test_orchestrator_raises_deadline_exceeded(tmp_path: Path) -> None:
    import dataclasses

    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    orchestrator = AgentOrchestrator(store, mode=PentestMode.STANDARD)
    # Force an already-expired deadline via a real ModeConfig copy
    orchestrator._config = dataclasses.replace(
        orchestrator._config, max_run_seconds=-1
    )

    run_id = "sf_pentest_deadline1"

    from sentinelforge.control.models import PentestRunRequest

    store.create_pentest_run(run_id, PentestRunRequest(repository="."))

    # Give the orchestrator a slow first handler so deadline triggers
    def _slow_handler(run_id, config, state):
        time.sleep(0.05)
        return {}

    orchestrator.register_handler(Phase.INIT, _slow_handler)

    # plan_phases returns INIT first; deadline check happens before phase 2
    import asyncio

    with pytest.raises(RunDeadlineExceeded):
        asyncio.run(orchestrator.execute(run_id, {}))

    kinds = [
        e.kind for e in store.list_events(run_id)
    ]
    assert "run_deadline_exceeded" in kinds


def test_deadline_does_not_trigger_when_within_budget(tmp_path: Path) -> None:
    store = SQLiteRunStore(tmp_path / "runs.sqlite3")
    orchestrator = AgentOrchestrator(store, mode=PentestMode.QUICK)
    run_id = "sf_pentest_deadline2"

    from sentinelforge.control.models import PentestRunRequest

    store.create_pentest_run(run_id, PentestRunRequest(repository="."))

    import asyncio

    state = asyncio.run(orchestrator.execute(run_id, {}))
    assert state.current_phase is not None
    kinds = [e.kind for e in store.list_events(run_id)]
    assert "run_deadline_exceeded" not in kinds

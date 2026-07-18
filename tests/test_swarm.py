from __future__ import annotations

import asyncio

from sentinelforge.event_bus import EventBus
from sentinelforge.swarm import AgentSwarm, SwarmTask


def _bus() -> EventBus:
    bus = EventBus.instance()
    return bus


def test_swarm_executes_all_tasks() -> None:
    bus = _bus()
    swarm = AgentSwarm(
        run_id="test_run",
        bus=bus,
        phase="testing",
        max_concurrency=3,
        requests_per_second=100,
        kill_switch_file="/nonexistent/STOP",
    )
    tasks = [
        SwarmTask(
            task_id=f"t{i}",
            agent_role="test_agent",
            description=f"task {i}",
            target=f"target_{i}",
            work=lambda i=i: i * 2,
        )
        for i in range(6)
    ]
    result = asyncio.run(swarm.execute(tasks))
    assert result.total == 6
    assert result.completed == 6
    assert result.failed == 0
    assert sorted(result.outputs) == [0, 2, 4, 6, 8, 10]


def test_swarm_handles_failures_gracefully() -> None:
    bus = _bus()
    swarm = AgentSwarm(
        run_id="test_run",
        bus=bus,
        phase="testing",
        max_concurrency=2,
        requests_per_second=100,
        kill_switch_file="/nonexistent/STOP",
    )

    def _boom() -> None:
        raise RuntimeError("intentional failure")

    tasks = [
        SwarmTask(
            task_id="ok",
            agent_role="a",
            description="ok",
            target="t1",
            work=lambda: 42,
        ),
        SwarmTask(
            task_id="bad",
            agent_role="a",
            description="bad",
            target="t2",
            work=_boom,
        ),
    ]
    result = asyncio.run(swarm.execute(tasks))
    assert result.completed == 1
    assert result.failed == 1
    failed = [r for r in result.results if r.status == "failed"]
    assert "intentional failure" in failed[0].error


def test_swarm_emits_lifecycle_events() -> None:
    bus = _bus()
    run_id = "test_events_run"
    bus.clear_log(run_id)
    queue = bus.subscribe(run_id)
    try:
        swarm = AgentSwarm(
            run_id=run_id,
            bus=bus,
            phase="testing",
            max_concurrency=2,
            requests_per_second=100,
            kill_switch_file="/nonexistent/STOP",
        )
        tasks = [
            SwarmTask(
                task_id="t1",
                agent_role="agent_x",
                description="d",
                target="t",
                work=lambda: 1,
            )
        ]
        asyncio.run(swarm.execute(tasks))
        kinds = [e.kind for e in bus.get_log(run_id)]
        assert "swarm_launched" in kinds
        assert "swarm_agent_spawned" in kinds
        assert "swarm_agent_completed" in kinds
        assert "swarm_finished" in kinds
    finally:
        bus.unsubscribe(run_id, queue)
        bus.clear_log(run_id)


def test_swarm_kill_switch(tmp_path) -> None:
    stop = tmp_path / "STOP"
    stop.write_text("halt")
    bus = _bus()
    swarm = AgentSwarm(
        run_id="test_run",
        bus=bus,
        phase="testing",
        max_concurrency=2,
        requests_per_second=100,
        kill_switch_file=str(stop),
    )
    tasks = [
        SwarmTask(
            task_id="t1",
            agent_role="a",
            description="d",
            target="t",
            work=lambda: 1,
        )
    ]
    result = asyncio.run(swarm.execute(tasks))
    assert result.failed == 1
    assert result.results[0].error == "kill_switch_engaged"

import asyncio
from pathlib import Path

from sentinelforge.control.storage import SQLiteRunStore
from sentinelforge.scheduler import PentestScheduler


def _make_store(tmp_path: Path) -> SQLiteRunStore:
    return SQLiteRunStore(tmp_path / "runs.sqlite3")


def test_create_schedule(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)

    schedule = sched.create_schedule(
        repository="examples/vulnerable_shop",
        scope_file="config/scope.yaml",
        mode="standard",
        interval_minutes=60,
    )
    assert schedule.schedule_id.startswith("sf_sched_")
    assert schedule.repository == "examples/vulnerable_shop"
    assert schedule.mode == "standard"
    assert schedule.interval_minutes == 60
    assert schedule.enabled is True


def test_list_schedules(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)

    sched.create_schedule(
        repository="repo1",
        scope_file="config/scope.yaml",
        mode="quick",
        interval_minutes=30,
    )
    sched.create_schedule(
        repository="repo2",
        scope_file="config/scope.yaml",
        mode="full",
        interval_minutes=120,
    )

    schedules = sched.list_schedules()
    assert len(schedules) == 2


def test_delete_schedule(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)

    schedule = sched.create_schedule(
        repository="repo",
        scope_file="config/scope.yaml",
        mode="standard",
        interval_minutes=60,
    )
    assert sched.delete_schedule(schedule.schedule_id) is True
    assert sched.list_schedules() == []


def test_delete_nonexistent_schedule(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)
    assert sched.delete_schedule("nonexistent") is False


def test_schedule_to_dict(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)

    schedule = sched.create_schedule(
        repository="repo",
        scope_file="config/scope.yaml",
        mode="standard",
        interval_minutes=60,
        metadata={"trigger": "manual"},
    )
    d = schedule.model_dump()
    assert d["schedule_id"].startswith("sf_sched_")
    assert d["metadata"]["trigger"] == "manual"


def test_enabled_only_filter(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)

    sched.create_schedule(
        repository="repo1",
        scope_file="config/scope.yaml",
        mode="quick",
        interval_minutes=30,
    )
    sched.create_schedule(
        repository="repo2",
        scope_file="config/scope.yaml",
        mode="full",
        interval_minutes=120,
    )

    store.update_pentest_schedule(
        sched.list_schedules()[0].schedule_id,
        enabled=False,
    )

    enabled = sched.list_schedules(enabled_only=True)
    assert len(enabled) == 1
    assert enabled[0].repository == "repo2"


def test_scheduled_run_preserves_selected_mode(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    sched = PentestScheduler(store)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        """\
target:
  base_url: "http://127.0.0.1:8000"
allowed_hosts: ["127.0.0.1"]
test_identities: []
""",
        encoding="utf-8",
    )
    schedule = sched.create_schedule(
        repository=str(tmp_path),
        scope_file=str(scope_path),
        mode="full",
        interval_minutes=60,
    )
    captured = {}

    def execute(request, scope, current_schedule) -> None:
        captured["request"] = request
        captured["schedule"] = current_schedule

    sched.set_executor(execute)
    asyncio.run(sched._run_schedule(schedule))

    assert captured["request"].mode.value == "full"
    assert captured["schedule"].schedule_id == schedule.schedule_id

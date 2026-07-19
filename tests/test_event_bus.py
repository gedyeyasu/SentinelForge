from __future__ import annotations

import asyncio
import threading
import time

from sentinelforge.event_bus import EventBus, LiveEvent


def _event(run_id: str, kind: str) -> LiveEvent:
    return LiveEvent(
        run_id=run_id,
        phase="test",
        kind=kind,
        timestamp=time.time(),
        payload={"message": kind},
    )


def test_publish_from_background_thread_is_received() -> None:
    """Regression: asyncio.Queue silently dropped cross-thread puts.

    The pentest/scan background threads publish while the SSE generator
    drains from the event loop. SimpleQueue must deliver every event.
    """
    bus = EventBus()
    received: list[str] = []
    errors: list[Exception] = []

    def publisher() -> None:
        for i in range(20):
            bus.publish(_event("run1", f"event_{i}"))

    q = bus.subscribe("run1")
    t = threading.Thread(target=publisher)
    t.start()
    t.join(timeout=5)

    deadline = time.time() + 3
    import queue as _queue

    while len(received) < 20 and time.time() < deadline:
        try:
            event = q.get_nowait()
            received.append(event.kind)
        except _queue.Empty:
            time.sleep(0.01)

    assert not errors
    assert len(received) == 20
    assert received[0] == "event_0"
    assert received[-1] == "event_19"


def test_subscribe_replays_history() -> None:
    bus = EventBus()
    bus.publish(_event("run2", "first"))
    bus.publish(_event("run2", "second"))
    q = bus.subscribe("run2")
    assert q.get_nowait().kind == "first"
    assert q.get_nowait().kind == "second"


def test_send_done_terminates() -> None:
    bus = EventBus()
    q = bus.subscribe("run3")
    bus.send_done("run3")
    assert q.get_nowait() is None


def test_async_drain_pattern_matches_sse_generator() -> None:
    """Verify the exact drain pattern used by the SSE endpoints works
    when events are published from another thread."""
    bus = EventBus()

    def publisher() -> None:
        time.sleep(0.05)
        for i in range(5):
            bus.publish(_event("run4", f"evt_{i}"))
        bus.send_done("run4")

    async def drain() -> list[str]:
        import queue as _queue

        q = bus.subscribe("run4")
        kinds: list[str] = []
        while True:
            try:
                event = q.get_nowait()
            except _queue.Empty:
                await asyncio.sleep(0.01)
                continue
            if event is None:
                break
            kinds.append(event.kind)
        return kinds

    t = threading.Thread(target=publisher)
    t.start()
    kinds = asyncio.run(asyncio.wait_for(drain(), timeout=5))
    t.join(timeout=5)
    assert kinds == [f"evt_{i}" for i in range(5)]


def test_get_log_preserves_all_events() -> None:
    bus = EventBus()
    for i in range(10):
        bus.publish(_event("run5", f"e{i}"))
    log = bus.get_log("run5")
    assert len(log) == 10
    bus.clear_log("run5")
    assert bus.get_log("run5") == []

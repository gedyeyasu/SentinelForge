from __future__ import annotations

import json
import logging
import queue
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LiveEvent:
    run_id: str
    phase: str
    kind: str
    timestamp: float
    payload: dict[str, Any]

    def to_sse(self) -> str:
        data = json.dumps({
            "run_id": self.run_id,
            "phase": self.phase,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "payload": self.payload,
        })
        return f"data: {data}\n\n"


class EventBus:
    """In-memory pub/sub for streaming pentest events to SSE clients.

    Uses queue.SimpleQueue, which is thread-safe: publish() is called from
    background worker threads (pentest/scan/swarm) while SSE generators
    drain queues from the asyncio event loop. asyncio.Queue is NOT safe
    for that pattern — cross-thread put_nowait silently drops wakeups.
    """

    _instance: EventBus | None = None

    def __init__(self) -> None:
        self._subscribers: dict[str, list[queue.SimpleQueue]] = defaultdict(list)
        self._event_log: dict[str, list[LiveEvent]] = defaultdict(list)

    @classmethod
    def instance(cls) -> EventBus:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def publish(self, event: LiveEvent) -> None:
        self._event_log[event.run_id].append(event)
        queues = self._subscribers.get(event.run_id, [])
        for q in queues:
            try:
                q.put_nowait(event)
            except Exception:
                logger.debug("Dropping event for subscriber: %s", event.kind)

    def subscribe(self, run_id: str) -> queue.SimpleQueue:
        q: queue.SimpleQueue = queue.SimpleQueue()
        self._subscribers[run_id].append(q)
        # Replay history after registering so nothing published between
        # subscribe and replay is lost (a rare duplicate is acceptable).
        for event in self._event_log.get(run_id, []):
            q.put_nowait(event)
        return q

    def unsubscribe(self, run_id: str, queue_obj: queue.SimpleQueue) -> None:
        subs = self._subscribers.get(run_id, [])
        if queue_obj in subs:
            subs.remove(queue_obj)

    def send_done(self, run_id: str) -> None:
        queues = self._subscribers.get(run_id, [])
        for q in queues:
            try:
                q.put_nowait(None)
            except Exception:
                pass

    def get_log(self, run_id: str) -> list[LiveEvent]:
        return list(self._event_log.get(run_id, []))

    def clear_log(self, run_id: str) -> None:
        self._event_log.pop(run_id, None)

from __future__ import annotations

import asyncio
import json
import logging
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
    """In-memory pub/sub for streaming pentest events to SSE clients."""

    _instance: EventBus | None = None

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[LiveEvent | None]]] = defaultdict(list)
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
            except asyncio.QueueFull:
                logger.debug("Dropping event for full queue: %s", event.kind)

    def subscribe(self, run_id: str) -> asyncio.Queue[LiveEvent | None]:
        q: asyncio.Queue[LiveEvent | None] = asyncio.Queue(maxsize=256)
        self._subscribers[run_id].append(q)
        # Replay any existing events for this run
        for event in self._event_log.get(run_id, []):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                break
        return q

    def unsubscribe(self, run_id: str, queue: asyncio.Queue[LiveEvent | None]) -> None:
        subs = self._subscribers.get(run_id, [])
        if queue in subs:
            subs.remove(queue)

    def send_done(self, run_id: str) -> None:
        queues = self._subscribers.get(run_id, [])
        for q in queues:
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

    def get_log(self, run_id: str) -> list[LiveEvent]:
        return list(self._event_log.get(run_id, []))

    def clear_log(self, run_id: str) -> None:
        self._event_log.pop(run_id, None)

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class ExploitOutcome(StrEnum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass(frozen=True)
class ExploitReceipt:
    receipt_id: str
    finding_id: str
    agent_role: str
    target_url: str
    method: str
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int
    response_body: str
    identity_used: str
    expected_invariant: str
    observed_behavior: str
    outcome: ExploitOutcome
    confidence: float
    replay_command: str
    evidence_hash: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result

    @staticmethod
    def compute_hash(
        method: str,
        url: str,
        headers: dict[str, str],
        body: str | None,
        response_status: int,
        response_body: str,
    ) -> str:
        canonical = json.dumps(
            {
                "method": method,
                "url": url,
                "headers": {k.lower(): v for k, v in sorted(headers.items())},
                "body": body,
                "response_status": response_status,
                "response_body": response_body[:4096],
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


def generate_replay_command(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None = None,
) -> str:
    parts = ["curl", "-X", method.upper(), url]
    for key, value in sorted(headers.items()):
        parts.extend(["-H", f"{key}: {value}"])
    if body:
        parts.extend(["-d", body])
    return " ".join(parts)

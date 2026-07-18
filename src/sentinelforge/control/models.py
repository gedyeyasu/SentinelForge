from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RunLifecycle(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityVerdict(StrEnum):
    SAFE = "safe"
    BLOCKED = "blocked"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"


class IntegrationHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"


class DetectionRunRequest(BaseModel):
    repository: str = Field(min_length=1)
    remediate: bool = True


class RunRecord(BaseModel):
    run_id: str
    repository: str
    lifecycle: RunLifecycle
    candidate_verdict: SecurityVerdict
    patch_verdict: SecurityVerdict
    integration_health: IntegrationHealth
    created_at: str
    updated_at: str
    result: dict[str, object] | None = None
    error: str | None = None


class RunEvent(BaseModel):
    sequence: int
    run_id: str
    phase: str
    kind: str
    occurred_at: str
    payload: dict[str, object]

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


class PentestStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PentestPhase(StrEnum):
    SCOPING = "scoping"
    MAPPING = "mapping"
    ATTACKING = "attacking"
    REPLAYING = "replaying"
    ATTESTED = "attested"


class PentestMode(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    TARGETED = "targeted"
    PRE_RELEASE = "pre_release"
    CONTINUOUS = "continuous"


class PentestRunRequest(BaseModel):
    repository: str = Field(min_length=1)
    scope_file: str = Field(default="config/scope.yaml")
    attack_only_source: bool = False
    mode: PentestMode = Field(default=PentestMode.STANDARD)


class PentestRunRecord(BaseModel):
    run_id: str
    repository: str
    scope_file: str
    status: PentestStatus
    phase: PentestPhase
    candidate_verdict: SecurityVerdict
    mode: str = "standard"
    created_at: str
    updated_at: str
    results: dict[str, object] | None = None
    error: str | None = None


class PentestScheduleRecord(BaseModel):
    schedule_id: str
    repository: str
    scope_file: str
    mode: str
    interval_minutes: int
    enabled: bool
    created_at: str
    last_run_at: str | None = None
    next_run_at: str
    metadata: dict[str, object] = Field(default_factory=dict)

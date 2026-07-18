from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from sentinelforge.domain import Finding


class ProposedFile(BaseModel):
    path: str = Field(min_length=1)
    content: str


class PatchProposal(BaseModel):
    finding_id: str
    provider: str
    model: str
    rationale: str
    files: list[ProposedFile] = Field(min_length=1, max_length=4)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int


class PatchProposer(Protocol):
    def propose(self, finding: Finding, repository_root: str) -> PatchProposal: ...

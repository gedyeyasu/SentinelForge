from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, Field


class RedHatAdvisory(BaseModel):
    advisory_id: str
    severity: str
    released_on: str
    cves: list[str]
    released_packages: list[str]
    resource_url: str


class _RedHatAdvisoryPayload(BaseModel):
    rhsa: str = Field(alias="RHSA")
    severity: str
    released_on: str
    cves: list[str] = Field(alias="CVEs")
    released_packages: list[str]
    resource_url: str


class RedHatSecurityDataClient:
    """Bounded read-only adapter for Red Hat's public CSAF index."""

    def __init__(
        self,
        *,
        base_url: str = "https://access.redhat.com/hydra/rest/securitydata",
        timeout_seconds: float = 15,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "SentinelForge/0.1"},
        )

    def list_advisories(
        self,
        *,
        package: str | None = None,
        created_days_ago: int = 30,
        per_page: int = 10,
    ) -> list[RedHatAdvisory]:
        if not 1 <= created_days_ago <= 365:
            raise ValueError("created_days_ago must be between 1 and 365")
        if not 1 <= per_page <= 25:
            raise ValueError("per_page must be between 1 and 25")
        params: dict[str, str | int] = {
            "created_days_ago": created_days_ago,
            "per_page": per_page,
            "isCompressed": "false",
        }
        if package:
            normalized = package.strip()
            if not normalized or len(normalized) > 80:
                raise ValueError("package filter must be between 1 and 80 characters")
            if not all(character.isalnum() or character in "-+._" for character in normalized):
                raise ValueError("package filter contains unsupported characters")
            params["package"] = normalized
        response = self._client.get(f"{self.base_url}/csaf.json", params=params)
        response.raise_for_status()
        payload: Any = response.json()
        if not isinstance(payload, list):
            raise ValueError("Red Hat CSAF index response was not a list")
        advisories: list[RedHatAdvisory] = []
        for raw in payload:
            parsed = _RedHatAdvisoryPayload.model_validate(raw)
            advisories.append(
                RedHatAdvisory(
                    advisory_id=parsed.rhsa,
                    severity=parsed.severity,
                    released_on=parsed.released_on,
                    cves=parsed.cves,
                    released_packages=parsed.released_packages,
                    resource_url=parsed.resource_url,
                )
            )
        return advisories

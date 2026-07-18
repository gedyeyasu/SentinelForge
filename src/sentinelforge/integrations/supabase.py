from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    publishable_key: str
    secret_key: str
    db_string: str

    @property
    def configured(self) -> bool:
        return bool(self.url and (self.publishable_key or self.secret_key))


def resolve_supabase_config() -> SupabaseConfig:
    return SupabaseConfig(
        url=os.environ.get("SUPABASE_URL", "").strip(),
        publishable_key=os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip(),
        secret_key=os.environ.get("SUPABASE_SECRET_KEY", "").strip(),
        db_string=os.environ.get("DB_STRING", "").strip(),
    )


class SupabaseClient:
    """Lightweight Supabase REST client for persisting pentest results."""

    def __init__(
        self,
        *,
        config: SupabaseConfig | None = None,
        timeout_seconds: float = 30,
        client: httpx.Client | None = None,
    ) -> None:
        self._config = config or resolve_supabase_config()
        self._client = client or httpx.Client(timeout=timeout_seconds)

    @property
    def configured(self) -> bool:
        return self._config.configured

    def _headers(self, *, use_service_key: bool = False) -> dict[str, str]:
        key = self._config.secret_key if use_service_key else self._config.publishable_key
        return {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    def health(self) -> dict[str, object]:
        if not self.configured:
            return {"status": "not_configured"}
        try:
            response = self._client.get(
                f"{self._config.url}/rest/v1/",
                headers=self._headers(),
            )
            return {
                "status": "healthy" if response.status_code in (200, 404) else "error",
                "status_code": response.status_code,
            }
        except Exception as error:
            return {"status": "error", "error": str(error)}

    def upsert_pentest_result(
        self,
        *,
        run_id: str,
        repository: str,
        mode: str,
        status: str,
        verdict: str,
        results: dict[str, Any],
    ) -> dict[str, Any]:
        if not self.configured:
            return {"status": "skipped", "reason": "not_configured"}
        payload = {
            "run_id": run_id,
            "repository": repository,
            "mode": mode,
            "status": status,
            "verdict": verdict,
            "results": json.dumps(results),
        }
        try:
            response = self._client.post(
                f"{self._config.url}/rest/v1/pentest_results",
                headers=self._headers(use_service_key=True),
                json=payload,
            )
            return {"status": "ok", "status_code": response.status_code}
        except Exception as error:
            return {"status": "error", "error": str(error)}

    def query_pentest_results(
        self,
        *,
        repository: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self.configured:
            return []
        params: dict[str, str] = {
            "order": "created_at.desc",
            "limit": str(limit),
        }
        if repository:
            params["repository"] = f"eq.{repository}"
        try:
            response = self._client.get(
                f"{self._config.url}/rest/v1/pentest_results",
                headers=self._headers(),
                params=params,
            )
            if response.status_code == 200:
                return response.json()
            return []
        except Exception:
            return []

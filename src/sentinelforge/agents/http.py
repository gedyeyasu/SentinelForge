from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from sentinelforge.policy import PolicyDecision, PolicyEngine


@dataclass(frozen=True)
class ScopedResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    duration_ms: int
    policy_decision: PolicyDecision


class ScopedHTTPClient:
    def __init__(
        self, policy: PolicyEngine, client: httpx.Client | None = None, runtime_security: object | None = None
    ) -> None:
        self._policy = policy
        self._client = client or httpx.Client(
            timeout=10,
            follow_redirects=False,
            headers={"User-Agent": "SentinelForge-AttackAgent/0.1"},
        )
        # HiddenLayer Runtime Security Track 3: instrument tool calls and results
        if runtime_security:
            self._runtime = runtime_security
        else:
            try:
                from sentinelforge.integrations.hiddenlayer_runtime import (
                    HiddenLayerRuntimeSecurity,
                )

                self._runtime = HiddenLayerRuntimeSecurity()
            except Exception:
                self._runtime = None

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: str | bytes | None = None,
    ) -> ScopedResponse:
        # HiddenLayer Track 3: Evaluate tool call (HTTP request) before it enters runtime
        if self._runtime:
            try:
                tool_check = self._runtime.evaluate_tool_call(
                    "http_request",
                    {"method": method, "url": url, "headers": headers, "content": str(content)[:2000] if content else ""},
                    {"provider": "sentinelforge", "model": "http-agent"},
                )
                if tool_check.action == "block":
                    # Block malicious tool call - thoughtful response per Track 3
                    return ScopedResponse(
                        status_code=0,
                        headers={},
                        body=f"Blocked by HiddenLayer runtime: {tool_check.signals}",
                        duration_ms=0,
                        policy_decision=self._policy.evaluate(method, url, destructive=False, dos_like=False),
                    )
            except Exception:
                pass

        decision = self._policy.evaluate(
            method,
            url,
            destructive=False,
            dos_like=False,
        )
        if not decision.allowed:
            return ScopedResponse(
                status_code=0,
                headers={},
                body="",
                duration_ms=0,
                policy_decision=decision,
            )

        started = time.monotonic()
        try:
            response = self._client.request(
                method,
                url,
                headers=headers or {},
                content=content,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            self._policy.record_request()
            scoped_resp = ScopedResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:10_000],
                duration_ms=duration_ms,
                policy_decision=decision,
            )

            # HiddenLayer Track 3: Evaluate tool result (HTTP response) - ingested content could contain prompt injection
            if self._runtime:
                try:
                    result_check = self._runtime.evaluate_tool_result(
                        "http_request",
                        response.text[:5000],
                        {"provider": "sentinelforge", "model": "http-agent"},
                    )
                    if result_check.verdict in ("malicious", "blocked"):
                        # Quarantine malicious tool result - don't feed back to agent context
                        scoped_resp = ScopedResponse(
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            body=f"[QUARANTINED by HiddenLayer: {result_check.signals}]",
                            duration_ms=duration_ms,
                            policy_decision=decision,
                        )
                except Exception:
                    pass

            return scoped_resp
        except httpx.HTTPError as error:
            duration_ms = int((time.monotonic() - started) * 1000)
            return ScopedResponse(
                status_code=0,
                headers={},
                body=str(error),
                duration_ms=duration_ms,
                policy_decision=decision,
            )

    def get(self, url: str, **kwargs: object) -> ScopedResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: object) -> ScopedResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: object) -> ScopedResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: object) -> ScopedResponse:
        return self.request("DELETE", url, **kwargs)

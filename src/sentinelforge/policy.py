from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from sentinelforge.scope import ScopeConfig, scope_matches_host


class PolicyVerdict(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class DenialReason(StrEnum):
    OUT_OF_SCOPE_HOST = "out_of_scope_host"
    FORBIDDEN_METHOD = "forbidden_method"
    FORBIDDEN_PATH = "forbidden_path"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    REQUEST_LIMIT_EXCEEDED = "request_limit_exceeded"
    KILL_SWITCH_ACTIVE = "kill_switch_active"
    DESTRUCTIVE_PAYLOAD_BLOCKED = "destructive_payload_blocked"
    DOS_BLOCKED = "dos_blocked"
    PRIVATE_ADDRESS_BLOCKED = "private_address_blocked"


@dataclass(frozen=True)
class PolicyDecision:
    verdict: PolicyVerdict
    reason: DenialReason | None = None
    detail: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is PolicyVerdict.ALLOWED

    @staticmethod
    def allow() -> PolicyDecision:
        return PolicyDecision(verdict=PolicyVerdict.ALLOWED)

    @staticmethod
    def deny(reason: DenialReason, detail: str = "") -> PolicyDecision:
        return PolicyDecision(verdict=PolicyVerdict.DENIED, reason=reason, detail=detail)


_PRIVATE_NETWORKS = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "169.254.",
    "0.",
)


def _is_private_address(hostname: str) -> bool:
    lower = hostname.lower()
    if lower in ("localhost", "::1"):
        return True
    return any(lower.startswith(prefix) for prefix in _PRIVATE_NETWORKS)


class PolicyEngine:
    def __init__(self, scope: ScopeConfig) -> None:
        self._scope = scope
        self._request_count = 0
        self._request_timestamps: list[float] = []
        self._kill_switch_active = False

    @property
    def scope(self) -> ScopeConfig:
        return self._scope

    @property
    def request_count(self) -> int:
        return self._request_count

    def check_kill_switch(self) -> PolicyDecision:
        if self._kill_switch_active:
            return PolicyDecision.deny(
                DenialReason.KILL_SWITCH_ACTIVE, "Kill switch is active"
            )
        kill_path = Path(self._scope.kill_switch_file)
        if kill_path.exists():
            self._kill_switch_active = True
            return PolicyDecision.deny(
                DenialReason.KILL_SWITCH_ACTIVE,
                f"Kill switch file detected at {kill_path}",
            )
        return PolicyDecision.allow()

    def evaluate(
        self,
        method: str,
        url: str,
        *,
        destructive: bool = False,
        dos_like: bool = False,
    ) -> PolicyDecision:
        kill = self.check_kill_switch()
        if not kill.allowed:
            return kill

        method_upper = method.upper()

        if method_upper not in self._scope.allowed_methods:
            return PolicyDecision.deny(
                DenialReason.FORBIDDEN_METHOD,
                f"Method {method_upper} not in allowed methods: {self._scope.allowed_methods}",
            )

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or "/"

        if not scope_matches_host(self._scope, hostname):
            if _is_private_address(hostname):
                return PolicyDecision.deny(
                    DenialReason.PRIVATE_ADDRESS_BLOCKED,
                    f"Private/loopback address blocked: {hostname}",
                )
            return PolicyDecision.deny(
                DenialReason.OUT_OF_SCOPE_HOST,
                f"Host {hostname!r} is not in allowed hosts: {self._scope.allowed_hosts}",
            )

        for forbidden in self._scope.forbidden_paths:
            if path.startswith(forbidden):
                return PolicyDecision.deny(
                    DenialReason.FORBIDDEN_PATH,
                    f"Path {path!r} matches forbidden path {forbidden!r}",
                )

        if destructive and not self._scope.allow_destructive_payloads:
            return PolicyDecision.deny(
                DenialReason.DESTRUCTIVE_PAYLOAD_BLOCKED,
                "Destructive payloads are not allowed by scope",
            )

        if dos_like and not self._scope.allow_denial_of_service:
            return PolicyDecision.deny(
                DenialReason.DOS_BLOCKED,
                "Denial-of-service patterns are not allowed by scope",
            )

        now = time.monotonic()
        cutoff = now - 1.0
        self._request_timestamps = [
            ts for ts in self._request_timestamps if ts > cutoff
        ]

        if self._request_count >= self._scope.max_total_requests:
            return PolicyDecision.deny(
                DenialReason.REQUEST_LIMIT_EXCEEDED,
                f"Total request limit {self._scope.max_total_requests} exceeded",
            )

        if len(self._request_timestamps) >= self._scope.max_requests_per_second:
            return PolicyDecision.deny(
                DenialReason.RATE_LIMIT_EXCEEDED,
                f"Rate limit {self._scope.max_requests_per_second} req/s exceeded",
            )

        return PolicyDecision.allow()

    def record_request(self) -> None:
        self._request_count += 1
        self._request_timestamps.append(time.monotonic())

    def remaining_budget(self) -> dict[str, int]:
        now = time.monotonic()
        cutoff = now - 1.0
        recent = sum(1 for ts in self._request_timestamps if ts > cutoff)
        return {
            "requests_remaining": max(
                0, self._scope.max_total_requests - self._request_count
            ),
            "per_second_remaining": max(
                0, self._scope.max_requests_per_second - recent
            ),
        }

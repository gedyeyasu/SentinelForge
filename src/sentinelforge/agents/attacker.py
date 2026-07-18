from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from sentinelforge.agents import ExploitOutcome, ExploitReceipt, generate_replay_command
from sentinelforge.agents.discovery import DiscoveredRoute
from sentinelforge.agents.http import ScopedHTTPClient
from sentinelforge.scope import ScopeConfig, TestIdentity


@dataclass
class AuthAttackResult:
    route: DiscoveredRoute
    receipts: list[ExploitReceipt]
    attack_count: int
    success_count: int
    blocked_count: int
    duration_ms: int


class AuthAttacker:
    AGENT_ROLE = "auth_attacker"

    def __init__(self, scope: ScopeConfig, client: ScopedHTTPClient) -> None:
        self._scope = scope
        self._client = client

    def attack_route(
        self,
        route: DiscoveredRoute,
        *,
        owner_identity: TestIdentity,
        attacker_identity: TestIdentity,
    ) -> AuthAttackResult:
        base_url = self._scope.target.base_url.rstrip("/")
        owner_url = route.example_url(base_url)
        attacker_url = route.example_url(base_url)

        started = time.monotonic()
        receipts: list[ExploitReceipt] = []

        owner_response = self._client.get(
            owner_url,
            headers=owner_identity.auth_header(),
        )

        attacker_response = self._client.get(
            attacker_url,
            headers=attacker_identity.auth_header(),
        )

        receipt = self._evaluate_cross_tenant_access(
            route,
            owner_url,
            owner_identity,
            attacker_url,
            attacker_identity,
            owner_response,
            attacker_response,
        )
        receipts.append(receipt)

        duration_ms = int((time.monotonic() - started) * 1000)

        success_count = sum(
            1 for r in receipts if r.outcome is ExploitOutcome.SUCCESS
        )
        blocked_count = sum(
            1 for r in receipts if r.outcome is ExploitOutcome.BLOCKED
        )

        return AuthAttackResult(
            route=route,
            receipts=receipts,
            attack_count=len(receipts),
            success_count=success_count,
            blocked_count=blocked_count,
            duration_ms=duration_ms,
        )

    def attack_routes(
        self,
        routes: list[DiscoveredRoute],
        *,
        owner_identity: TestIdentity | None = None,
        attacker_identity: TestIdentity | None = None,
    ) -> list[AuthAttackResult]:
        identities = list(self._scope.test_identities)
        if len(identities) < 2:
            return []

        owner = owner_identity or identities[0]
        attacker = attacker_identity or identities[1]

        results: list[AuthAttackResult] = []
        for route in routes:
            if not route.path_params:
                continue
            result = self.attack_route(
                route,
                owner_identity=owner,
                attacker_identity=attacker,
            )
            results.append(result)
        return results

    def _evaluate_cross_tenant_access(
        self,
        route: DiscoveredRoute,
        owner_url: str,
        owner: TestIdentity,
        attacker_url: str,
        attacker: TestIdentity,
        owner_response: object,
        attacker_response: object,
    ) -> ExploitReceipt:
        owner_status = owner_response.status_code if hasattr(owner_response, "status_code") else 0
        owner_body = owner_response.body if hasattr(owner_response, "body") else ""
        attacker_status = (
            attacker_response.status_code
            if hasattr(attacker_response, "status_code")
            else 0
        )
        attacker_body = attacker_response.body if hasattr(attacker_response, "body") else ""
        attacker_duration = (
            attacker_response.duration_ms if hasattr(attacker_response, "duration_ms") else 0
        )
        attacker_decision = (
            attacker_response.policy_decision
            if hasattr(attacker_response, "policy_decision")
            else None
        )

        if attacker_decision and not attacker_decision.allowed:
            receipt_hash = ExploitReceipt.compute_hash(
                "GET", attacker_url, attacker.auth_header(), None, 0, ""
            )
            return ExploitReceipt(
                receipt_id="receipt_" + receipt_hash[:16],
                finding_id=self._finding_id(route),
                agent_role=self.AGENT_ROLE,
                target_url=attacker_url,
                method="GET",
                request_headers=attacker.auth_header(),
                request_body=None,
                response_status=0,
                response_body="",
                identity_used=attacker.name,
                expected_invariant="Cross-tenant access must be denied",
                observed_behavior=f"Request blocked by policy: {attacker_decision.reason}",
                outcome=ExploitOutcome.BLOCKED,
                confidence=1.0,
                replay_command="",
                evidence_hash=receipt_hash,
                duration_ms=0,
            )

        success = (
            owner_status == 200
            and attacker_status == 200
            and owner_status == attacker_status
            and owner_body == attacker_body
        )
        blocked = (
            owner_status == 200
            and attacker_status in (403, 404)
        )

        if success:
            outcome = ExploitOutcome.SUCCESS
            observed = (
                f"Attacker received the same {attacker_status} response as the owner. "
                "Cross-tenant authorization is missing."
            )
            confidence = 0.92
        elif blocked:
            outcome = ExploitOutcome.BLOCKED
            observed = (
                f"Attacker received {attacker_status} while owner received {owner_status}. "
                "Cross-tenant access is denied."
            )
            confidence = 0.95
        else:
            outcome = ExploitOutcome.BLOCKED
            observed = (
                f"Attacker received {attacker_status}, owner received {owner_status}. "
                "Access pattern does not indicate a cross-tenant authorization flaw."
            )
            confidence = 0.70

        receipt_hash = ExploitReceipt.compute_hash(
            "GET", attacker_url, attacker.auth_header(), None, attacker_status, attacker_body
        )
        replay_cmd = generate_replay_command(
            "GET", attacker_url, attacker.auth_header()
        )

        return ExploitReceipt(
            receipt_id="receipt_" + receipt_hash[:16],
            finding_id=self._finding_id(route),
            agent_role=self.AGENT_ROLE,
            target_url=attacker_url,
            method="GET",
            request_headers=attacker.auth_header(),
            request_body=None,
            response_status=attacker_status,
            response_body=attacker_body[:4096],
            identity_used=attacker.name,
            expected_invariant="Cross-tenant access must be denied",
            observed_behavior=observed,
            outcome=outcome,
            confidence=confidence,
            replay_command=replay_cmd,
            evidence_hash=receipt_hash,
            duration_ms=attacker_duration,
        )

    @staticmethod
    def _finding_id(route: DiscoveredRoute) -> str:
        input_str = f"auth:{route.method}:{route.path}"
        return "sf_auth_" + hashlib.sha256(input_str.encode()).hexdigest()[:12]

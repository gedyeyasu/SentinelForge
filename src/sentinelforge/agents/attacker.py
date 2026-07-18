from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any

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
    techniques_tested: list[str] = None


class AuthAttacker:
    AGENT_ROLE = "auth_attacker"
    TECHNIQUES = [
        "direct_bola",
        "id_enumeration",
        "id_zero",
        "header_tenant_injection",
        "jwt_tenant_swap",
        "verb_tamper",
        "param_pollution",
    ]

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
        started = time.monotonic()
        receipts: list[ExploitReceipt] = []
        techniques: list[str] = []

        # 1. Direct BOLA: same ID, attacker header vs owner header
        receipts.append(self._try_direct_bola(route, base_url, owner_identity, attacker_identity))
        techniques.append("direct_bola")

        # 2. ID Enumeration: try id-1, id+1, id=0, id=1 if path has {id}
        if route.path_params:
            for technique, variant_url in self._id_enumeration_urls(route, base_url):
                rec = self._try_with_url(route, variant_url, owner_identity, attacker_identity, technique)
                receipts.append(rec)
                techniques.append(technique)

        # 3. Header tenant injection: x-tenant-id swap, x-user-id swap
        rec = self._try_header_injection(route, base_url, owner_identity, attacker_identity)
        receipts.append(rec)
        techniques.append("header_tenant_injection")

        # 4. JWT tenant claim swap (if auth header looks like Bearer)
        rec = self._try_jwt_swap(route, base_url, owner_identity, attacker_identity)
        if rec:
            receipts.append(rec)
            techniques.append("jwt_tenant_swap")

        # 5. Verb tampering: try PUT/PATCH on GET endpoint with attacker identity
        if route.method == "GET":
            for verb in ["PUT", "PATCH", "POST"]:
                rec = self._try_verb_tamper(route, base_url, verb, attacker_identity)
                receipts.append(rec)
                techniques.append(f"verb_tamper_{verb.lower()}")

        # 6. Param pollution: add ?tenant_id=attacker or ?user_id=attacker
        rec = self._try_param_pollution(route, base_url, owner_identity, attacker_identity)
        receipts.append(rec)
        techniques.append("param_pollution")

        duration_ms = int((time.monotonic() - started) * 1000)
        success_count = sum(1 for r in receipts if r.outcome is ExploitOutcome.SUCCESS)
        blocked_count = sum(1 for r in receipts if r.outcome is ExploitOutcome.BLOCKED)

        return AuthAttackResult(
            route=route,
            receipts=receipts,
            attack_count=len(receipts),
            success_count=success_count,
            blocked_count=blocked_count,
            duration_ms=duration_ms,
            techniques_tested=techniques,
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
            if not route.path_params and route.method not in ("GET", "PUT", "PATCH"):
                # Still test non-param routes for header injection
                if route.method not in ("GET", "POST"):
                    continue
            result = self.attack_route(
                route,
                owner_identity=owner,
                attacker_identity=attacker,
            )
            results.append(result)
        return results

    # ---- Technique helpers ----

    def _try_direct_bola(
        self,
        route: DiscoveredRoute,
        base_url: str,
        owner: TestIdentity,
        attacker: TestIdentity,
    ) -> ExploitReceipt:
        owner_url = route.example_url(base_url)
        attacker_url = route.example_url(base_url)
        owner_resp = self._client.get(owner_url, headers=owner.auth_header())
        attacker_resp = self._client.get(attacker_url, headers=attacker.auth_header())
        return self._evaluate(
            route, owner_url, owner, attacker_url, attacker, owner_resp, attacker_resp, "direct_bola"
        )

    def _id_enumeration_urls(self, route: DiscoveredRoute, base_url: str) -> list[tuple[str, str]]:
        base = route.example_url(base_url)
        urls = []
        # Try to extract numeric id from example_url
        m = re.search(r"/(\d+)(?:\?|$)", base)
        if m:
            orig_id = int(m.group(1))
            for variant in [orig_id - 1, orig_id + 1, 0, 1]:
                if variant < 0:
                    continue
                urls.append((f"id_enumeration_{variant}", base.replace(f"/{orig_id}", f"/{variant}", 1)))
        else:
            # Fallback: replace {id} style with known ids
            for vid in [1, 2, 999]:
                urls.append((f"id_enumeration_{vid}", re.sub(r"\{[a-z_]+id\}", str(vid), base, flags=re.I)))
        return urls

    def _try_with_url(
        self,
        route: DiscoveredRoute,
        attacker_url: str,
        owner: TestIdentity,
        attacker: TestIdentity,
        technique: str,
    ) -> ExploitReceipt:
        owner_url = route.example_url(self._scope.target.base_url.rstrip("/"))
        owner_resp = self._client.get(owner_url, headers=owner.auth_header())
        attacker_resp = self._client.get(attacker_url, headers=attacker.auth_header())
        return self._evaluate(route, owner_url, owner, attacker_url, attacker, owner_resp, attacker_resp, technique)

    def _try_header_injection(
        self,
        route: DiscoveredRoute,
        base_url: str,
        owner: TestIdentity,
        attacker: TestIdentity,
    ) -> ExploitReceipt:
        owner_url = route.example_url(base_url)
        # Attacker tries to use owner's tenant header or inject x-tenant-id
        injected_headers = dict(attacker.auth_header())
        injected_headers["x-tenant-id"] = owner.tenant_id
        injected_headers["x-original-user"] = owner.name
        owner_resp = self._client.get(owner_url, headers=owner.auth_header())
        attacker_resp = self._client.get(owner_url, headers=injected_headers)
        return self._evaluate(route, owner_url, owner, owner_url, attacker, owner_resp, attacker_resp, "header_tenant_injection", extra_headers=injected_headers)

    def _try_jwt_swap(
        self,
        route: DiscoveredRoute,
        base_url: str,
        owner: TestIdentity,
        attacker: TestIdentity,
    ) -> ExploitReceipt | None:
        owner_headers = owner.auth_header()
        attacker_headers = attacker.auth_header()
        # Check if any header looks like Bearer JWT (3 dot parts)
        has_jwt = any("Bearer" in str(v) or str(v).count(".") == 2 for v in attacker_headers.values())
        if not has_jwt:
            # Still simulate JWT tenant swap via custom header enumeration
            pass
        url = route.example_url(base_url)
        # Simulate tampered token: attacker token with owner tenant claim
        tampered_headers = dict(attacker_headers)
        tampered_headers["x-jwt-tenant-claim"] = owner.tenant_id
        owner_resp = self._client.get(url, headers=owner_headers)
        attacker_resp = self._client.get(url, headers=tampered_headers)
        return self._evaluate(route, url, owner, url, attacker, owner_resp, attacker_resp, "jwt_tenant_swap", extra_headers=tampered_headers)

    def _try_verb_tamper(
        self,
        route: DiscoveredRoute,
        base_url: str,
        verb: str,
        attacker: TestIdentity,
    ) -> ExploitReceipt:
        url = route.example_url(base_url)
        # Use GET to fetch owner baseline
        owner_resp = self._client.get(url, headers=attacker.auth_header())
        # Try verb tamper
        if verb == "POST":
            attacker_resp = self._client.request(verb, url, headers=attacker.auth_header(), content="{}")
        else:
            attacker_resp = self._client.request(verb, url, headers=attacker.auth_header())
        return self._evaluate(route, url, attacker, url, attacker, owner_resp, attacker_resp, f"verb_tamper_{verb.lower()}")

    def _try_param_pollution(
        self,
        route: DiscoveredRoute,
        base_url: str,
        owner: TestIdentity,
        attacker: TestIdentity,
    ) -> ExploitReceipt:
        base = route.example_url(base_url)
        polluted = base + ("&" if "?" in base else "?") + f"tenant_id={attacker.tenant_id}&user_id={owner.name}"
        owner_resp = self._client.get(base, headers=owner.auth_header())
        attacker_resp = self._client.get(polluted, headers=attacker.auth_header())
        return self._evaluate(route, base, owner, polluted, attacker, owner_resp, attacker_resp, "param_pollution")

    def _evaluate(
        self,
        route: DiscoveredRoute,
        owner_url: str,
        owner: TestIdentity,
        attacker_url: str,
        attacker: TestIdentity,
        owner_response: Any,
        attacker_response: Any,
        technique: str = "direct_bola",
        extra_headers: dict[str, str] | None = None,
    ) -> ExploitReceipt:
        owner_status = getattr(owner_response, "status_code", 0)
        owner_body = getattr(owner_response, "body", "")
        attacker_status = getattr(attacker_response, "status_code", 0)
        attacker_body = getattr(attacker_response, "body", "")
        attacker_duration = getattr(attacker_response, "duration_ms", 0)
        attacker_decision = getattr(attacker_response, "policy_decision", None)

        headers_used = extra_headers or attacker.auth_header()

        if attacker_decision and not attacker_decision.allowed:
            receipt_hash = ExploitReceipt.compute_hash("GET", attacker_url, headers_used, None, 0, "")
            return ExploitReceipt(
                receipt_id="receipt_" + receipt_hash[:16],
                finding_id=self._finding_id(route, technique),
                agent_role=self.AGENT_ROLE,
                target_url=attacker_url,
                method="GET",
                request_headers=headers_used,
                request_body=None,
                response_status=0,
                response_body="",
                identity_used=attacker.name,
                expected_invariant="Cross-tenant access must be denied",
                observed_behavior=f"Blocked by policy ({technique}): {attacker_decision.reason}",
                outcome=ExploitOutcome.BLOCKED,
                confidence=1.0,
                replay_command="",
                evidence_hash=receipt_hash,
                duration_ms=0,
            )

        success = (
            owner_status == 200
            and attacker_status == 200
            and owner_body == attacker_body
            and owner_body != ""
        )
        blocked = owner_status == 200 and attacker_status in (403, 404, 401)

        if success:
            outcome = ExploitOutcome.SUCCESS
            observed = f"[{technique}] Attacker got same 200 as owner. BOLA missing. Owner {owner_status} len={len(str(owner_body))}, Attacker {attacker_status} len={len(str(attacker_body))}"
            confidence = 0.92 if technique == "direct_bola" else 0.85
        elif blocked:
            outcome = ExploitOutcome.BLOCKED
            observed = f"[{technique}] Blocked: attacker {attacker_status} vs owner {owner_status}"
            confidence = 0.95
        else:
            outcome = ExploitOutcome.BLOCKED
            observed = f"[{technique}] Not vulnerable pattern: owner {owner_status}, attacker {attacker_status}"
            confidence = 0.70

        receipt_hash = ExploitReceipt.compute_hash("GET", attacker_url, headers_used, None, attacker_status, attacker_body)
        replay_cmd = generate_replay_command("GET", attacker_url, headers_used)

        return ExploitReceipt(
            receipt_id="receipt_" + receipt_hash[:16],
            finding_id=self._finding_id(route, technique),
            agent_role=self.AGENT_ROLE,
            target_url=attacker_url,
            method="GET",
            request_headers=headers_used,
            request_body=None,
            response_status=attacker_status,
            response_body=str(attacker_body)[:4096],
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
    def _finding_id(route: DiscoveredRoute, technique: str) -> str:
        input_str = f"auth:{technique}:{route.method}:{route.path}"
        return "sf_auth_" + hashlib.sha256(input_str.encode()).hexdigest()[:12]

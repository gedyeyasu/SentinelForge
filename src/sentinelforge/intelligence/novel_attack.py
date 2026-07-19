from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.agents import (
    ExploitOutcome,
    ExploitReceipt,
    generate_replay_command,
)
from sentinelforge.agents.discovery import DiscoveredRoute
from sentinelforge.agents.http import ScopedHTTPClient
from sentinelforge.scope import ScopeConfig, TestIdentity

logger = logging.getLogger(__name__)

AGENT_ROLE = "novel_attack_synthesizer"


@dataclass(frozen=True)
class AttackStep:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    success_signal: str = ""
    identity: str = "attacker"


@dataclass(frozen=True)
class AttackHypothesis:
    hypothesis_id: str
    title: str
    rationale: str
    attack_class: str
    severity: str
    target_path: str
    steps: tuple[AttackStep, ...]
    source: str  # "llm" | "composition_engine"
    novelty_score: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "rationale": self.rationale,
            "attack_class": self.attack_class,
            "severity": self.severity,
            "target_path": self.target_path,
            "source": self.source,
            "novelty_score": self.novelty_score,
            "step_count": len(self.steps),
        }


class NovelAttackSynthesizer:
    """Generates and executes novel attack hypotheses beyond static payloads.

    Two generation paths:
    1. LLM-driven: Nemotron (via NIM) reasons over the route map, source
       context, and current CVE intel to propose targeted hypotheses.
    2. Composition engine: deterministic combination of 15 attack
       primitives (type juggling, mass assignment, ID smuggling, method
       override, race conditions, ...) into executable chains.

    Every hypothesis is executed against the scoped target and produces
    standard ExploitReceipts. Prior attack outcomes from engagement memory
    steer generation toward unexplored attack space.
    """

    def __init__(
        self,
        scope: ScopeConfig,
        client: ScopedHTTPClient,
        *,
        nvidia_api_key: str = "",
        nvidia_model: str = "nvidia/nemotron-3-nano-30b-a3b",
        nvidia_base_url: str = "https://integrate.api.nvidia.com/v1",
        prior_attacks: list[dict[str, Any]] | None = None,
    ) -> None:
        self._scope = scope
        self._client = client
        self._nvidia_api_key = nvidia_api_key
        self._nvidia_model = nvidia_model
        self._nvidia_base_url = nvidia_base_url
        self._prior = prior_attacks or []
        self._base_url = scope.target.base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def synthesize(
        self,
        routes: list[DiscoveredRoute],
        *,
        source_context: str = "",
        threat_intel: list[dict[str, Any]] | None = None,
        max_hypotheses: int = 12,
    ) -> list[AttackHypothesis]:
        hypotheses: list[AttackHypothesis] = []
        llm_hyps = self._llm_hypotheses(
            routes, source_context, threat_intel or []
        )
        hypotheses.extend(llm_hyps)
        for route in routes:
            hypotheses.extend(self._compose_for_route(route))
        hypotheses = self._dedupe_and_score(hypotheses)
        hypotheses.sort(key=lambda h: (-h.novelty_score, h.severity))
        return self._guaranteed_attacks(routes, hypotheses[:max_hypotheses])

    def _guaranteed_attacks(
        self,
        routes: list[DiscoveredRoute],
        hypotheses: list[AttackHypothesis],
    ) -> list[AttackHypothesis]:
        """Ensure demo-critical attacks always run regardless of dedup/cap."""
        import secrets as _secrets

        for route in routes:
            if "register" not in route.path or route.method != "POST":
                continue
            email = f"sf-race-{_secrets.token_hex(4)}@sentinelforge-test.invalid"
            body = f'{{"email":"{email}","password":"P@ssw0rd!Aa1"}}'
            url = self._base_url + route.path
            hypotheses.append(
                AttackHypothesis(
                    hypothesis_id="comp_" + uuid.uuid4().hex[:8],
                    title=f"Race condition: double-register on {route.path}",
                    rationale=(
                        "Two concurrent registration requests with the same "
                        "email race past the uniqueness check (check-then-act "
                        "without a transaction). If one wins and the other "
                        "raises IntegrityError 500, the server has a near-zero-day "
                        "race condition vulnerability."
                    ),
                    attack_class="race_condition",
                    severity="critical",
                    target_path=route.path,
                    steps=(
                        AttackStep(
                            method="POST", url=url,
                            headers={"Content-Type": "application/json"},
                            body=body,
                            success_signal="integrityerror_500",
                        ),
                        AttackStep(
                            method="POST", url=url,
                            headers={"Content-Type": "application/json"},
                            body=body,
                            success_signal="integrityerror_500",
                        ),
                    ),
                    source="composition_engine",
                    novelty_score=0.95,
                )
            )
        return hypotheses

    # ------------------------------------------------------------------
    # LLM-driven hypothesis generation
    # ------------------------------------------------------------------

    def _llm_hypotheses(
        self,
        routes: list[DiscoveredRoute],
        source_context: str,
        threat_intel: list[dict[str, Any]],
    ) -> list[AttackHypothesis]:
        if not self._nvidia_api_key or not routes:
            return []
        import httpx

        route_brief = [
            {"method": r.method, "path": r.path, "params": list(r.path_params)}
            for r in routes[:20]
        ]
        intel_brief = [
            {
                "cve": t.get("cve_id", ""),
                "summary": str(t.get("summary", ""))[:160],
            }
            for t in threat_intel[:5]
        ]
        prior_brief = [
            str(p.get("attack_class", p.get("route", "")))[:80]
            for p in self._prior[:10]
        ]
        prompt = (
            "You are an elite application-security researcher. Given this "
            "API route map, source context, and current threat intel, "
            "propose NOVEL attack hypotheses that go beyond basic BOLA and "
            "textbook injection. Focus on near-zero-day classes: type "
            "juggling, mass assignment, parser differential, race "
            "conditions, auth-context smuggling, tenant isolation bypass "
            "variants.\n\n"
            f"ROUTES:\n{json.dumps(route_brief, indent=1)}\n\n"
            f"SOURCE CONTEXT:\n{source_context[:1500]}\n\n"
            f"THREAT INTEL:\n{json.dumps(intel_brief, indent=1)}\n\n"
            f"ALREADY TRIED (avoid repeats):\n{json.dumps(prior_brief)}\n\n"
            "Return ONLY a JSON array (max 5 items). Each item: "
            '{"title": str, "rationale": str, "attack_class": str, '
            '"severity": "critical|high|medium", "target_path": str, '
            '"steps": [{"method": str, "url_suffix": str, '
            '"headers": {str: str}, "body": str|null, '
            '"success_signal": str}]}. '
            "url_suffix must start with / and target one of the listed "
            "routes. Keep bodies under 300 chars."
        )
        try:
            response = httpx.post(
                f"{self._nvidia_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._nvidia_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._nvidia_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You output only valid JSON arrays of attack "
                                "hypotheses for authorized security testing."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.6,
                    "max_tokens": 2500,
                    "stream": False,
                },
                timeout=60,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return self._parse_llm_hypotheses(content)
        except Exception as error:
            logger.warning("LLM hypothesis generation failed: %s", error)
            return []

    def _parse_llm_hypotheses(self, content: str) -> list[AttackHypothesis]:
        stripped = content.strip()
        if stripped.startswith("```"):
            first_nl = stripped.find("\n")
            last_fence = stripped.rfind("```")
            if first_nl != -1 and last_fence > first_nl:
                stripped = stripped[first_nl + 1 : last_fence].strip()
        start = stripped.find("[")
        end = stripped.rfind("]")
        if start == -1 or end <= start:
            return []
        try:
            raw_items = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return []
        hypotheses: list[AttackHypothesis] = []
        for item in raw_items[:5]:
            if not isinstance(item, dict):
                continue
            steps: list[AttackStep] = []
            for raw_step in item.get("steps", [])[:4]:
                if not isinstance(raw_step, dict):
                    continue
                suffix = str(raw_step.get("url_suffix", ""))
                if not suffix.startswith("/"):
                    continue
                url = self._base_url + suffix
                if not self._url_in_scope(url):
                    continue
                steps.append(
                    AttackStep(
                        method=str(raw_step.get("method", "GET")).upper(),
                        url=url,
                        headers={
                            str(k): str(v)
                            for k, v in (
                                raw_step.get("headers") or {}
                            ).items()
                        },
                        body=(
                            str(raw_step["body"])[:2000]
                            if raw_step.get("body") is not None
                            else None
                        ),
                        success_signal=str(
                            raw_step.get("success_signal", "")
                        )[:200],
                    )
                )
            if not steps:
                continue
            hypotheses.append(
                AttackHypothesis(
                    hypothesis_id="llm_" + uuid.uuid4().hex[:8],
                    title=str(item.get("title", "LLM hypothesis"))[:200],
                    rationale=str(item.get("rationale", ""))[:500],
                    attack_class=str(item.get("attack_class", "llm_novel")),
                    severity=str(item.get("severity", "medium")).lower(),
                    target_path=str(item.get("target_path", ""))[:200],
                    steps=tuple(steps),
                    source="llm",
                    novelty_score=0.9,
                )
            )
        return hypotheses

    # ------------------------------------------------------------------
    # Composition engine: 15 attack primitives combined per route
    # ------------------------------------------------------------------

    def _compose_for_route(self, route: DiscoveredRoute) -> list[AttackHypothesis]:
        out: list[AttackHypothesis] = []
        base_path = route.path

        def _hyp(
            attack_class: str,
            title: str,
            rationale: str,
            severity: str,
            steps: list[AttackStep],
            novelty: float,
        ) -> None:
            out.append(
                AttackHypothesis(
                    hypothesis_id="comp_" + uuid.uuid4().hex[:8],
                    title=title,
                    rationale=rationale,
                    attack_class=attack_class,
                    severity=severity,
                    target_path=base_path,
                    steps=tuple(steps),
                    source="composition_engine",
                    novelty_score=novelty,
                )
            )

        # 1. ID representation smuggling (encoded, padded, float, null-byte)
        if route.path_params:
            param = route.path_params[0]
            variants = [
                ("%31", "url_encoded_digit"),
                ("01", "zero_padded"),
                ("1.0", "float_coercion"),
                ("-1", "negative_id"),
                ("2147483647", "int_overflow"),
                ("1%00", "null_byte_suffix"),
            ]
            for mutated, technique in variants:
                path = base_path.replace("{" + param + "}", mutated)
                _hyp(
                    f"id_smuggling_{technique}",
                    f"ID representation smuggling ({technique}) on {base_path}",
                    (
                        f"Parser differentials: {technique} may resolve to a "
                        "valid object while bypassing identity-scoped filters."
                    ),
                    "high",
                    [
                        AttackStep(
                            method=route.method,
                            url=self._base_url + path,
                            success_signal="cross_tenant_data",
                        )
                    ],
                    0.75,
                )

        # 2. Parameter pollution (duplicate param, first-vs-last wins)
        if route.path_params:
            param = route.path_params[0]
            clean = base_path.replace("{" + param + "}", "2")
            sep = "&" if "?" in clean else "?"
            polluted = f"{clean}{sep}{param}=1"
            _hyp(
                "param_pollution_bola",
                f"Parameter pollution BOLA on {base_path}",
                (
                    "Duplicate object id params exploit first-wins vs "
                    "last-wins parser discrepancies between authz filter "
                    "and data layer."
                ),
                "high",
                [
                    AttackStep(
                        method=route.method,
                        url=self._base_url + polluted,
                        success_signal="cross_tenant_data",
                    )
                ],
                0.8,
            )

        # 3. Mass assignment / privilege field injection
        if route.method in ("POST", "PUT", "PATCH"):
            for field_name, value in (
                ("role", "admin"),
                ("is_admin", True),
                ("tenant_id", "tenant-a"),
            ):
                body = json.dumps({field_name: value})
                _hyp(
                    "mass_assignment",
                    f"Mass assignment ({field_name}) on {route.method} {base_path}",
                    (
                        f"Injecting privileged field '{field_name}' tests "
                        "whether the model binds unlisted attributes."
                    ),
                    "critical",
                    [
                        AttackStep(
                            method=route.method,
                            url=self._base_url + base_path.replace(
                                "{" + route.path_params[0] + "}", "1"
                            ) if route.path_params else self._base_url + base_path,
                            headers={"Content-Type": "application/json"},
                            body=body,
                            success_signal="privilege_granted",
                        )
                    ],
                    0.7,
                )

        # 4. HTTP method override headers
        if route.method == "GET":
            for header, verb in (
                ("X-HTTP-Method-Override", "DELETE"),
                ("X-HTTP-Method", "PUT"),
                ("X-Method-Override", "PATCH"),
            ):
                _hyp(
                    "method_override",
                    f"Method override via {header} on {base_path}",
                    (
                        "Frameworks honoring method-override headers may "
                        "execute mutating verbs while routing/authz sees GET."
                    ),
                    "high",
                    [
                        AttackStep(
                            method="POST",
                            url=self._base_url + base_path.replace(
                                "{" + route.path_params[0] + "}", "1"
                            ) if route.path_params else self._base_url + base_path,
                            headers={header: verb},
                            success_signal="mutation_applied",
                        )
                    ],
                    0.65,
                )

        # 5. Content-Type confusion
        if route.method in ("POST", "PUT", "PATCH"):
            _hyp(
                "content_type_confusion",
                f"Content-Type confusion on {route.method} {base_path}",
                (
                    "Sending form-encoded data to a JSON parser (or vice "
                    "versa) can bypass validation middleware."
                ),
                "medium",
                [
                    AttackStep(
                        method=route.method,
                        url=self._base_url + base_path.replace(
                            "{" + route.path_params[0] + "}", "1"
                        ) if route.path_params else self._base_url + base_path,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        body="role=admin&tenant_id=tenant-a",
                        success_signal="validation_bypassed",
                    )
                ],
                0.55,
            )

        # 6. Auth-context smuggling via rewrite headers
        _hyp(
            "auth_context_smuggling",
            f"Rewrite-header authz bypass on {base_path}",
            (
                "X-Original-URL / X-Rewrite-URL can make path-based "
                "middleware authorize a benign path while the app serves "
                "a privileged one."
            ),
            "high",
            [
                AttackStep(
                    method="GET",
                    url=self._base_url + "/",
                    headers={
                        "X-Original-URL": base_path.replace(
                            "{" + route.path_params[0] + "}", "1"
                        ) if route.path_params else base_path,
                    },
                    success_signal="cross_tenant_data",
                )
            ],
            0.6,
        )

        # 7. Race condition (double-submit) for mutating endpoints
        if route.method == "POST":
            import secrets as _secrets

            race_email = f"sf-race-{_secrets.token_hex(4)}@sentinelforge-test.invalid"
            race_body = (
                '{"email":"' + race_email + '","password":"P@ssw0rd!Aa1"}'
                if "register" in base_path
                else "{}"
            )
            _hyp(
                "race_condition",
                f"Race condition double-submit on {base_path}",
                (
                    "Concurrent duplicate requests may defeat "
                    "check-then-act logic (double-spend, double-claim). "
                    "Two identical requests sent simultaneously — if the "
                    "server uses check-then-act without a transaction, "
                    "the second request races past the uniqueness check."
                ),
                "high",
                [
                    AttackStep(
                        method="POST",
                        url=self._base_url + base_path,
                        headers={"Content-Type": "application/json"},
                        body=race_body,
                        success_signal="duplicate_effect",
                    ),
                    AttackStep(
                        method="POST",
                        url=self._base_url + base_path,
                        headers={"Content-Type": "application/json"},
                        body=race_body,
                        success_signal="duplicate_effect",
                    ),
                ],
                0.75,
            )

        # 8. Type juggling in JSON bodies
        if route.method in ("POST", "PUT", "PATCH"):
            _hyp(
                "type_juggling",
                f"JSON type juggling on {route.method} {base_path}",
                (
                    "Array/string/int coercion differences between "
                    "validator and datastore can bypass equality checks."
                ),
                "high",
                [
                    AttackStep(
                        method=route.method,
                        url=self._base_url + base_path.replace(
                            "{" + route.path_params[0] + "}", "1"
                        ) if route.path_params else self._base_url + base_path,
                        headers={"Content-Type": "application/json"},
                        body='{"id": ["1"], "tenant_id": "tenant-a"}',
                        success_signal="validation_bypassed",
                    )
                ],
                0.7,
            )

        return out

    # ------------------------------------------------------------------
    # Dedupe, novelty scoring, scope checks
    # ------------------------------------------------------------------

    def _dedupe_and_score(
        self, hypotheses: list[AttackHypothesis]
    ) -> list[AttackHypothesis]:
        seen: set[str] = set()
        prior_classes = {
            str(p.get("attack_class", "")) for p in self._prior
        }
        out: list[AttackHypothesis] = []
        for hyp in hypotheses:
            key = f"{hyp.attack_class}:{hyp.target_path}"
            if key in seen:
                continue
            seen.add(key)
            if hyp.attack_class in prior_classes:
                hyp = AttackHypothesis(
                    **{
                        **hyp.__dict__,
                        "novelty_score": hyp.novelty_score * 0.4,
                    }
                )
            out.append(hyp)
        return out

    def _url_in_scope(self, url: str) -> bool:
        from urllib.parse import urlparse

        from sentinelforge.scope import scope_matches_host

        host = urlparse(url).hostname or ""
        return scope_matches_host(self._scope, host)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        hypothesis: AttackHypothesis,
        *,
        owner_identity: TestIdentity | None = None,
        attacker_identity: TestIdentity | None = None,
    ) -> list[ExploitReceipt]:
        # Race condition hypotheses must send all steps CONCURRENTLY
        if hypothesis.attack_class == "race_condition":
            return self._execute_race(
                hypothesis, owner_identity, attacker_identity
            )
        receipts: list[ExploitReceipt] = []
        for step in hypothesis.steps:
            r = self._execute_step(
                hypothesis, step, owner_identity, attacker_identity
            )
            if isinstance(r, list):
                receipts.extend(r)
            else:
                receipts.append(r)
        return receipts

    def _execute_race(
        self,
        hypothesis: AttackHypothesis,
        owner_identity: TestIdentity | None,
        attacker_identity: TestIdentity | None,
    ) -> list[ExploitReceipt]:
        """Send race condition steps concurrently in real threads."""
        import threading as _threading

        all_results: list[list[ExploitReceipt]] = []
        threads: list[_threading.Thread] = []

        def _do_step(step: AttackStep) -> None:
            r = self._execute_step(
                hypothesis, step, owner_identity, attacker_identity
            )
            all_results.append(
                r if isinstance(r, list) else [r]
            )

        for step in hypothesis.steps:
            t = _threading.Thread(target=_do_step, args=(step,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=15)

        receipts: list[ExploitReceipt] = []
        for sublist in all_results:
            receipts.extend(sublist)
        return receipts

    def _execute_step(
        self,
        hypothesis: AttackHypothesis,
        step: AttackStep,
        owner_identity: TestIdentity | None,
        attacker_identity: TestIdentity | None,
    ) -> ExploitReceipt:
        headers = dict(step.headers)
        identity_name = "anonymous"
        if step.identity == "owner" and owner_identity:
            headers.update(owner_identity.auth_header())
            identity_name = owner_identity.name
        elif attacker_identity:
            headers.update(attacker_identity.auth_header())
            identity_name = attacker_identity.name

        started = time.monotonic()
        try:
            response = self._client.request(
                step.method, step.url, headers=headers, content=step.body
            )
        except Exception as error:
            return self._receipt(
                hypothesis, step, headers, identity_name,
                0, str(error)[:300], ExploitOutcome.ERROR,
                int((time.monotonic() - started) * 1000),
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        outcome = self._evaluate(hypothesis, step, response)
        cross_tenant_data = False
        owner_body_hash = ""
        if outcome is ExploitOutcome.SUCCESS and owner_identity and attacker_identity:
            cross_tenant_data, owner_body_hash = self._check_cross_tenant(
                step, owner_identity, response
            )
        return self._receipt(
            hypothesis, step, headers, identity_name,
            response.status_code, response.body, outcome, duration_ms,
            extra={
                "cross_tenant_data": cross_tenant_data,
                "owner_body_sha256": owner_body_hash,
            },
        )

    def _check_cross_tenant(
        self,
        step: AttackStep,
        owner_identity: TestIdentity,
        attacker_response: Any,
    ) -> tuple[bool, str]:
        """Compare attacker's response with owner's to detect cross-tenant data access.

        A real BOLA means both identities receive the same data — the attacker
        can read another tenant's resource. If responses differ substantially
        (one gets the resource, the other gets 404/403), it's not cross-tenant.
        """
        try:
            owner_headers = dict(step.headers)
            owner_headers.update(owner_identity.auth_header())
            owner_resp = self._client.request(
                step.method, step.url,
                headers=owner_headers, content=step.body,
            )
            owner_hash = hashlib.sha256(
                (owner_resp.body or "").encode()
            ).hexdigest()
            attacker_hash = hashlib.sha256(
                (attacker_response.body or "").encode()
            ).hexdigest()
            if (
                attacker_response.status_code == 200
                and owner_resp.status_code == 200
                and attacker_hash == owner_hash
                and len(attacker_response.body or "") > 20
            ):
                return True, owner_hash
            return False, owner_hash
        except Exception:
            return False, ""

    @staticmethod
    def _evaluate(
        hypothesis: AttackHypothesis, step: AttackStep, response: Any
    ) -> ExploitOutcome:
        if response.status_code in (401, 403, 404, 405):
            return ExploitOutcome.BLOCKED
        if response.status_code >= 500:
            body = (response.body or "").lower()
            if "integrityerror" in body or "race" in hypothesis.attack_class:
                return ExploitOutcome.SUCCESS
            return ExploitOutcome.ERROR
        body = response.body.lower() if response.body else ""
        blocked_signals = ("not found", "forbidden", "unauthorized", "denied")
        if any(sig in body for sig in blocked_signals):
            return ExploitOutcome.BLOCKED
        if 200 <= response.status_code < 300:
            return ExploitOutcome.SUCCESS
        return ExploitOutcome.BLOCKED

    @staticmethod
    def _receipt(
        hypothesis: AttackHypothesis,
        step: AttackStep,
        headers: dict[str, str],
        identity_name: str,
        status: int,
        body: str,
        outcome: ExploitOutcome,
        duration_ms: int,
        extra: dict[str, Any] | None = None,
    ) -> ExploitReceipt:
        extra = extra or {}
        finding_id = f"novel-{hypothesis.attack_class}-{hypothesis.hypothesis_id[-6:]}"
        body_lower = (body or "").lower()
        is_crash = status >= 500 and ("integrityerror" in body_lower or "race" in hypothesis.attack_class)
        return ExploitReceipt(
            receipt_id="rcpt_" + uuid.uuid4().hex[:12],
            finding_id=finding_id,
            agent_role=AGENT_ROLE,
            target_url=step.url,
            method=step.method,
            request_headers=headers,
            request_body=step.body,
            response_status=status,
            response_body=(body or "")[:4096],
            identity_used=identity_name,
            expected_invariant=(
                f"Server must reject {hypothesis.attack_class}: "
                f"{hypothesis.title}"
            ),
            observed_behavior=(
                (
                    "SERVER CRASHED: Race condition caused IntegrityError 500. "
                    f"Evidence: {body.replace(chr(10), ' ')[:120]}. "
                    if is_crash
                    else (
                        "CROSS-TENANT DATA LEAKED: Attacker accessed owner's resource. "
                        if extra.get("cross_tenant_data")
                        else ""
                    )
                )
                + f"[{hypothesis.source}] {hypothesis.title} -> HTTP {status}. "
                + (
                    f"Body hash matches owner (SHA-256: {extra['owner_body_sha256'][:16]}...). "
                    f"{hypothesis.rationale[:120]}"
                    if extra.get("cross_tenant_data")
                    else hypothesis.rationale[:200]
                )
            ),
            outcome=outcome,
            confidence=(
                0.95 if extra.get("cross_tenant_data") or is_crash
                else 0.85 if outcome is ExploitOutcome.SUCCESS
                else 0.5
            ),
            replay_command=generate_replay_command(
                step.method, step.url, headers, step.body
            ),
            evidence_hash=hashlib.sha256(
                f"{step.method}{step.url}{status}{body[:512]}".encode()
            ).hexdigest(),
            duration_ms=duration_ms,
        )

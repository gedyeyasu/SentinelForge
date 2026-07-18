from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.intelligence.adaptive_payloads import AdaptivePayloadGenerator
from sentinelforge.intelligence.threat_learning import ThreatLearner

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    hypothesis_id: str
    description: str
    category: str
    confidence: float
    payloads_to_try: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    tested: bool = False
    confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "description": self.description,
            "category": self.category,
            "confidence": self.confidence,
            "payload_count": len(self.payloads_to_try),
            "tested": self.tested,
            "confirmed": self.confirmed,
            "evidence": self.evidence,
        }


class ZeroDayHunter:
    """Hypothesis-driven vulnerability exploration.

    Based on the Akira and FORGE patterns:
    - Generate hypotheses from threat intelligence
    - Wide exploration (WIDE phase)
    - Deep testing (DEEP phase)
    - Harvest results (HARVEST phase)
    """

    HYPOTHESIS_TEMPLATES = [
        {
            "category": "injection",
            "templates": [
                "Parameter '{param}' in {endpoint} may be vulnerable to {attack}",
                "Header '{header}' in {endpoint} may accept unsanitized input",
                "Body field '{field}' in {endpoint} may allow injection",
            ],
        },
        {
            "category": "authentication",
            "templates": [
                "Endpoint {endpoint} may lack authentication checks",
                "Token validation may be bypassed via {method}",
                "Session handling in {endpoint} may have flaws",
            ],
        },
        {
            "category": "authorization",
            "templates": [
                "User {user_type} may access {endpoint} without proper authorization",
                "Resource {resource} may be accessible across tenant boundaries",
                "Privilege escalation possible via {endpoint}",
            ],
        },
        {
            "category": "configuration",
            "templates": [
                "Debug mode may be enabled in {endpoint}",
                "Error messages in {endpoint} may leak sensitive information",
                "CORS policy may be too permissive in {endpoint}",
            ],
        },
    ]

    def __init__(
        self,
        *,
        threat_learner: ThreatLearner | None = None,
        payload_generator: AdaptivePayloadGenerator | None = None,
    ) -> None:
        self._threat_learner = threat_learner or ThreatLearner()
        self._payload_generator = payload_generator or AdaptivePayloadGenerator()
        self._hypotheses: list[Hypothesis] = []
        self._tested_count = 0
        self._confirmed_count = 0

    def generate_hypotheses(
        self,
        routes: list[dict[str, Any]],
        patterns: list[dict[str, Any]] | None = None,
    ) -> list[Hypothesis]:
        import hashlib

        new_hypotheses: list[Hypothesis] = []

        for route in routes:
            path = route.get("path", "")
            params = self._extract_params(route)

            for template_group in self.HYPOTHESIS_TEMPLATES:
                for template in template_group["templates"]:
                    for param in params[:3]:
                        desc = template.format(
                            param=param,
                            endpoint=path,
                            header=param,
                            field=param,
                            attack="injection",
                            method="token bypass",
                            user_type="authenticated",
                            resource=path,
                        )

                        hyp_id = hashlib.sha256(
                            f"{path}:{param}:{template_group['category']}".encode()
                        ).hexdigest()[:12]

                        existing_ids = {h.hypothesis_id for h in self._hypotheses}
                        if hyp_id in existing_ids:
                            continue

                        payloads = self._payload_generator.generate_payloads(
                            template_group["category"],
                            count=5,
                        ).payloads

                        hyp = Hypothesis(
                            hypothesis_id=hyp_id,
                            description=desc,
                            category=template_group["category"],
                            confidence=0.3,
                            payloads_to_try=payloads,
                        )
                        new_hypotheses.append(hyp)

        if patterns:
            for pattern in patterns[:10]:
                desc = f"Pattern match: {pattern.get('description', '')[:100]}"
                hyp_id = hashlib.sha256(desc.encode()).hexdigest()[:12]

                existing_ids = {h.hypothesis_id for h in self._hypotheses}
                if hyp_id in existing_ids:
                    continue

                payloads = self._payload_generator.generate_payloads(
                    pattern.get("type", "injection"),
                    count=3,
                ).payloads

                hyp = Hypothesis(
                    hypothesis_id=hyp_id,
                    description=desc,
                    category=pattern.get("type", "unknown"),
                    confidence=0.5,
                    payloads_to_try=payloads,
                )
                new_hypotheses.append(hyp)

        self._hypotheses.extend(new_hypotheses)
        return new_hypotheses

    def wide_exploration(
        self, routes: list[dict[str, Any]]
    ) -> list[Hypothesis]:
        hypotheses = self.generate_hypotheses(routes)
        return [h for h in hypotheses if not h.tested]

    def deep_exploration(
        self, hypothesis: Hypothesis, results: list[dict[str, Any]]
    ) -> Hypothesis:
        hypothesis.tested = True
        self._tested_count += 1

        for result in results:
            if result.get("success"):
                hypothesis.confirmed = True
                hypothesis.confidence = min(1.0, hypothesis.confidence + 0.3)
                hypothesis.evidence.append(result.get("evidence", ""))
                self._confirmed_count += 1

                self._payload_generator.update_effectiveness(
                    hypothesis.category,
                    result.get("payload", ""),
                    success=True,
                )
            else:
                hypothesis.confidence = max(0.0, hypothesis.confidence - 0.1)
                self._payload_generator.update_effectiveness(
                    hypothesis.category,
                    result.get("payload", ""),
                    success=False,
                )

        return hypothesis

    def harvest_results(self) -> dict[str, Any]:
        confirmed = [h for h in self._hypotheses if h.confirmed]
        high_confidence = [h for h in self._hypotheses if h.confidence >= 0.7]

        return {
            "total_hypotheses": len(self._hypotheses),
            "tested": self._tested_count,
            "confirmed": self._confirmed_count,
            "high_confidence": len(high_confidence),
            "confirmed_hypotheses": [h.to_dict() for h in confirmed],
            "effectiveness_report": self._payload_generator.get_effectiveness_report(),
        }

    def get_untested(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses if not h.tested]

    def get_confirmed(self) -> list[Hypothesis]:
        return [h for h in self._hypotheses if h.confirmed]

    def _extract_params(self, route: dict[str, Any]) -> list[str]:
        params: list[str] = []
        path = route.get("path", "")
        parts = path.split("/")
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                params.append(part[1:-1])

        params.extend(["id", "user_id", "token", "q", "search", "page"])
        return params

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypotheses": [h.to_dict() for h in self._hypotheses],
            "tested_count": self._tested_count,
            "confirmed_count": self._confirmed_count,
        }

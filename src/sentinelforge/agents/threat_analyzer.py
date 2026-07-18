from __future__ import annotations

import json
import time
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError
from pydantic import Field as PydanticField


class ThreatAssessment(BaseModel):
    risk_level: str = PydanticField(min_length=1)
    summary: str = PydanticField(min_length=1)
    attack_vectors: list[str] = PydanticField(default_factory=list)
    recommendations: list[str] = PydanticField(default_factory=list)
    cvss_estimate: str = ""
    exploitability: str = ""


class NIMThreatAnalyzer:
    """Use NVIDIA Nemotron via NIM to analyze security findings."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "nvidia/nemotron-3-nano-30b-a3b",
        base_url: str = "https://integrate.api.nvidia.com/v1",
        timeout_seconds: float = 60,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("NVIDIA API key is required")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def health(self) -> dict[str, object]:
        try:
            response = self._client.get(
                f"{self.base_url}/models",
                headers=self._headers(),
            )
            response.raise_for_status()
            payload = response.json()
            model_ids = [item.get("id") for item in payload.get("data", [])]
            return {
                "provider": "nvidia_nim",
                "model": self.model,
                "available": self.model in model_ids,
            }
        except Exception as error:
            return {
                "provider": "nvidia_nim",
                "model": self.model,
                "available": False,
                "error": str(error),
            }

    def analyze_findings(
        self,
        *,
        findings_summary: dict[str, Any],
        dep_vulns: dict[str, Any] | None = None,
        pattern_findings: dict[str, Any] | None = None,
        injection_results: list[dict[str, Any]] | None = None,
        exploit_receipts: list[dict[str, Any]] | None = None,
    ) -> ThreatAssessment:
        prompt = self._build_analysis_prompt(
            findings_summary=findings_summary,
            dep_vulns=dep_vulns,
            pattern_findings=pattern_findings,
            injection_results=injection_results,
            exploit_receipts=exploit_receipts,
        )
        started = time.monotonic()
        response = self._client.post(
            f"{self.base_url}/chat/completions",
            headers=self._headers(),
            json={
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a senior application security engineer analyzing "
                            "vulnerability scan results. Provide concise, actionable "
                            "threat assessments. Return only the requested JSON."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.3,
                "top_p": 1.0,
                "top_k": 1,
                "max_tokens": 2048,
                "stream": False,
            },
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        response.raise_for_status()
        body = response.json()
        content = self._extract_content(body)
        return self._parse_assessment(content, latency_ms=latency_ms)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _build_analysis_prompt(
        *,
        findings_summary: dict[str, Any],
        dep_vulns: dict[str, Any] | None,
        pattern_findings: dict[str, Any] | None,
        injection_results: list[dict[str, Any]] | None,
        exploit_receipts: list[dict[str, Any]] | None,
    ) -> str:
        parts = [
            "Analyze these security scan results and provide a threat assessment.\n",
            f"SCAN RESULTS:\n"
            f"{json.dumps(findings_summary, indent=2, sort_keys=True)}\n",
        ]
        if dep_vulns:
            parts.append(
                "DEPENDENCY VULNERABILITIES:\n"
                f"{json.dumps(dep_vulns, indent=2, sort_keys=True)}\n"
            )
        if pattern_findings:
            parts.append(
                "EXPLOIT PATTERNS:\n"
                f"{json.dumps(pattern_findings, indent=2, sort_keys=True)}\n"
            )
        if injection_results:
            parts.append(
                "INJECTION TEST RESULTS:\n"
                f"{json.dumps(injection_results, indent=2, sort_keys=True)}\n"
            )
        if exploit_receipts:
            parts.append(
                "EXPLOIT RECEIPTS:\n"
                f"{json.dumps(exploit_receipts, indent=2, sort_keys=True)}\n"
            )

        schema = {
            "risk_level": "critical|high|medium|low|info",
            "summary": "1-2 sentence summary",
            "attack_vectors": ["vector1", "vector2"],
            "recommendations": ["rec1", "rec2"],
            "cvss_estimate": "CVSS:3.1/AV:N/AC:L/...",
            "exploitability": "high|medium|low",
        }
        parts.append(
            f"Return only JSON matching this shape:\n{json.dumps(schema, indent=2)}"
        )
        return "\n".join(parts)

    @staticmethod
    def _extract_content(body: dict[str, Any]) -> str:
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise RuntimeError(
                "NIM response did not contain assistant content"
            ) from error
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("NIM response content was empty")
        return content

    @staticmethod
    def _parse_assessment(content: str, *, latency_ms: int = 0) -> ThreatAssessment:
        stripped = content.strip()
        if stripped.startswith("```"):
            first_newline = stripped.find("\n")
            last_fence = stripped.rfind("```")
            if first_newline != -1 and last_fence > first_newline:
                stripped = stripped[first_newline + 1 : last_fence].strip()
        try:
            raw = json.loads(stripped)
            return ThreatAssessment.model_validate(raw)
        except (json.JSONDecodeError, ValidationError):
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start != -1 and end > start:
                try:
                    raw = json.loads(stripped[start : end + 1])
                    return ThreatAssessment.model_validate(raw)
                except (json.JSONDecodeError, ValidationError):
                    pass
            raw_preview = stripped[:200]
            return ThreatAssessment(
                risk_level="medium",
                summary=(
                    f"Unable to parse NIM response. Latency: {latency_ms}ms. "
                    f"Raw: {raw_preview}"
                ),
                attack_vectors=["parse_error"],
                recommendations=["Review raw NIM output"],
            )

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx


class HiddenLayerVerdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


@dataclass(frozen=True)
class ScanResult:
    verdict: HiddenLayerVerdict
    score: float
    details: str
    scanner: str
    latency_ms: int


class HiddenLayerClient:
    """Bounded adapter for HiddenLayer model I/O defense.

    Scans prompts, tool calls, and repository content for:
    - Prompt injection attempts
    - Malicious instructions embedded in code
    - Unsafe model output patterns
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.hiddenlayer.com",
        timeout_seconds: float = 15,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("HIDDENLAYER_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
        )

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def scan_prompt(self, prompt: str) -> ScanResult:
        if not self.configured:
            return ScanResult(
                verdict=HiddenLayerVerdict.SAFE,
                score=0.0,
                details="HiddenLayer not configured; skipped",
                scanner="hiddenlayer_prompt",
                latency_ms=0,
            )

        return self._scan_with_payload(
            {
                "input": prompt,
                "scan_type": "prompt_injection",
            },
            scanner="hiddenlayer_prompt",
        )

    def scan_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> ScanResult:
        if not self.configured:
            return ScanResult(
                verdict=HiddenLayerVerdict.SAFE,
                score=0.0,
                details="HiddenLayer not configured; skipped",
                scanner="hiddenlayer_tool_call",
                latency_ms=0,
            )

        import json

        payload_str = json.dumps(
            {"tool": tool_name, "arguments": arguments}, sort_keys=True
        )
        return self._scan_with_payload(
            {
                "input": payload_str,
                "scan_type": "tool_call_safety",
            },
            scanner="hiddenlayer_tool_call",
        )

    def scan_content(self, content: str, source: str = "unknown") -> ScanResult:
        if not self.configured:
            return ScanResult(
                verdict=HiddenLayerVerdict.SAFE,
                score=0.0,
                details="HiddenLayer not configured; skipped",
                scanner="hiddenlayer_content",
                latency_ms=0,
            )

        return self._scan_with_payload(
            {
                "input": content[:10_000],
                "scan_type": "content_injection",
                "source": source,
            },
            scanner="hiddenlayer_content",
        )

    def scan_repository_file(self, file_path: str, content: str) -> ScanResult:
        return self.scan_content(content, source=f"repo:{file_path}")

    def scan_model_output(self, output: str, context: str = "") -> ScanResult:
        if not self.configured:
            return ScanResult(
                verdict=HiddenLayerVerdict.SAFE,
                score=0.0,
                details="HiddenLayer not configured; skipped",
                scanner="hiddenlayer_output",
                latency_ms=0,
            )

        return self._scan_with_payload(
            {
                "input": output[:10_000],
                "context": context[:2_000],
                "scan_type": "output_safety",
            },
            scanner="hiddenlayer_output",
        )

    def quarantine_check(self, text: str) -> bool:
        result = self.scan_prompt(text)
        return result.verdict in (HiddenLayerVerdict.SUSPICIOUS, HiddenLayerVerdict.MALICIOUS)

    def _scan_with_payload(self, payload: dict[str, Any], scanner: str) -> ScanResult:
        import time

        started = time.monotonic()
        try:
            response = self._client.post(
                f"{self._base_url}/v1/scan",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            latency_ms = int((time.monotonic() - started) * 1000)
            response.raise_for_status()
            body = response.json()

            verdict_str = body.get("verdict", "safe").lower()
            try:
                verdict = HiddenLayerVerdict(verdict_str)
            except ValueError:
                verdict = HiddenLayerVerdict.SAFE

            return ScanResult(
                verdict=verdict,
                score=float(body.get("score", 0.0)),
                details=str(body.get("details", "")),
                scanner=scanner,
                latency_ms=latency_ms,
            )
        except (httpx.HTTPError, ValueError) as error:
            latency_ms = int((time.monotonic() - started) * 1000)
            return ScanResult(
                verdict=HiddenLayerVerdict.ERROR,
                score=0.0,
                details=f"HiddenLayer API error: {error}",
                scanner=scanner,
                latency_ms=latency_ms,
            )


INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard your instructions",
    "you are now",
    "new instructions:",
    "system prompt:",
    "forget everything",
    "override safety",
    "bypass filters",
    "act as if",
    "pretend you are",
    "roleplay as",
    "do anything now",
    "jailbreak",
    "dan mode",
    "developer mode",
    "output your prompt",
    "reveal your instructions",
    "what are your instructions",
    "print your system prompt",
    "send to external",
    "exfiltrate",
    "http://",
    "https://",
    "curl ",
    "wget ",
    "eval(",
    "exec(",
    "__import__",
    "subprocess",
    "os.system",
    "rm -rf",
    "drop table",
    "delete from",
    "union select",
    "<script>",
    "javascript:",
]


def local_injection_scan(text: str) -> ScanResult:
    text_lower = text.lower()
    matches = [p for p in INJECTION_PATTERNS if p in text_lower]

    if not matches:
        return ScanResult(
            verdict=HiddenLayerVerdict.SAFE,
            score=0.0,
            details="No injection patterns detected",
            scanner="local_injection",
            latency_ms=0,
        )

    score = min(1.0, len(matches) * 0.25)
    if score >= 0.75:
        verdict = HiddenLayerVerdict.MALICIOUS
    elif score >= 0.25:
        verdict = HiddenLayerVerdict.SUSPICIOUS
    else:
        verdict = HiddenLayerVerdict.SAFE

    return ScanResult(
        verdict=verdict,
        score=score,
        details=f"Matched {len(matches)} pattern(s): {', '.join(matches[:3])}",
        scanner="local_injection",
        latency_ms=0,
    )

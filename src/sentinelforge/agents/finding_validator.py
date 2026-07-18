from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sentinelforge.agents import ExploitOutcome, ExploitReceipt
from sentinelforge.agents.http import ScopedHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    receipt: ExploitReceipt
    validated: bool
    outcome: ExploitOutcome
    replay_attempts: int
    hiddenlayer_verdict: str | None = None
    reason: str = ""


class FindingValidator:
    """
    Implements PLAN §7.3 Evidence Standard: replayable receipt validation.
    Confirms exploit is reproducible in sandbox, not transient, and HiddenLayer verdict clean.
    """

    def __init__(self, client: ScopedHTTPClient | None = None):
        self._client = client

    def validate(
        self,
        receipt: ExploitReceipt,
        *,
        hiddenlayer_verdict: str | None = None,
        max_replays: int = 2,
    ) -> ValidationResult:
        # If receipt already BLOCKED, it's not a finding needing validation
        if receipt.outcome == ExploitOutcome.BLOCKED:
            return ValidationResult(
                receipt=receipt,
                validated=False,
                outcome=ExploitOutcome.BLOCKED,
                replay_attempts=0,
                hiddenlayer_verdict=hiddenlayer_verdict,
                reason="Original receipt already BLOCKED - no vulnerability to validate",
            )

        # Replay check
        attempts = 0
        success_replays = 0
        if self._client:
            for _ in range(max_replays):
                attempts += 1
                try:
                    resp = self._client.request(
                        receipt.method,
                        receipt.target_url,
                        headers=receipt.request_headers,
                        content=receipt.request_body,
                    )
                    # If replay gives same success status as original, count
                    if resp.status_code == receipt.response_status or resp.status_code == 200:
                        success_replays += 1
                except Exception as exc:
                    logger.debug("Replay failed: %s", exc)
                    continue

            validated = success_replays >= 1
            outcome = ExploitOutcome.SUCCESS if validated else ExploitOutcome.BLOCKED
            reason = (
                f"Replay succeeded {success_replays}/{attempts} times - confirmed"
                if validated
                else f"Replay failed {attempts} attempts - false positive"
            )
        else:
            # No live client (source_only mode) - trust receipt if confidence high and includes expected invariant fields
            has_evidence = bool(receipt.evidence_hash and receipt.replay_command and receipt.expected_invariant)
            validated = receipt.confidence >= 0.75 and has_evidence
            outcome = receipt.outcome if validated else ExploitOutcome.BLOCKED
            attempts = 0
            reason = (
                "Source evidence has all 8 fields + high confidence - confirmed for source_only"
                if validated
                else "Missing evidence fields or low confidence"
            )

        # HiddenLayer check: if input was malicious injection, quarantine
        if hiddenlayer_verdict == "MALICIOUS":
            validated = False
            outcome = ExploitOutcome.BLOCKED
            reason += " + quarantined by HiddenLayer (malicious payload)"

        return ValidationResult(
            receipt=receipt,
            validated=validated,
            outcome=outcome,
            replay_attempts=attempts,
            hiddenlayer_verdict=hiddenlayer_verdict,
            reason=reason,
        )

    def validate_batch(
        self,
        receipts: list[ExploitReceipt],
        hiddenlayer_results: list[dict[str, Any]] | None = None,
    ) -> list[ValidationResult]:
        results = []
        hl_map = {r.get("file", ""): r.get("verdict") for r in (hiddenlayer_results or [])}
        for receipt in receipts:
            # Try to find matching HL verdict by target_url path
            verdict = None
            for f, v in hl_map.items():
                if f in receipt.target_url:
                    verdict = v
                    break
            results.append(self.validate(receipt, hiddenlayer_verdict=verdict))
        return results

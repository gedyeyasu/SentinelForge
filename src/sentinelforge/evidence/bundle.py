from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelforge.agents import ExploitReceipt


class EvidenceBundle:
    """Structured evidence package for one confirmed finding.

    Bundles receipts, request/response captures, hashes, and replay
    commands into a team-consumable directory with a Markdown report
    security engineers can attach to tickets or PRs.
    """

    def __init__(self, run_id: str, base_dir: Path | None = None) -> None:
        self.run_id = run_id
        self.base_dir = (
            base_dir or Path(".sentinelforge/evidence") / run_id
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
        sensitive = {"authorization", "cookie", "x-api-key", "set-cookie"}
        return {
            k: ("[REDACTED]" if k.lower() in sensitive else v)
            for k, v in headers.items()
        }

    def add_receipt(
        self,
        receipt: ExploitReceipt,
        *,
        agent_role: str = "",
        hypothesis: dict[str, Any] | None = None,
    ) -> Path:
        finding_dir = self.base_dir / receipt.finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)
        evidence = {
            "finding_id": receipt.finding_id,
            "run_id": self.run_id,
            "captured_at": datetime.now(UTC).isoformat(),
            "agent_role": agent_role or receipt.agent_role,
            "outcome": receipt.outcome.value,
            "confidence": receipt.confidence,
            "request": {
                "method": receipt.method,
                "url": receipt.target_url,
                "headers": self._redact_headers(receipt.request_headers),
                "body": receipt.request_body,
            },
            "response": {
                "status": receipt.response_status,
                "body_sha256": hashlib.sha256(
                    receipt.response_body.encode()
                ).hexdigest(),
                "body_preview": receipt.response_body[:1500],
            },
            "expected_invariant": receipt.expected_invariant,
            "observed_behavior": receipt.observed_behavior,
            "evidence_hash": receipt.evidence_hash,
            "replay_command": receipt.replay_command,
            "hypothesis": hypothesis or {},
        }
        evidence_path = finding_dir / "evidence.json"
        evidence_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return evidence_path

    def write_markdown_report(
        self,
        *,
        target: str,
        findings: list[dict[str, Any]],
    ) -> Path:
        lines = [
            f"# SentinelForge Evidence Report — {self.run_id}",
            "",
            f"- **Target:** {target}",
            f"- **Generated:** {datetime.now(UTC).isoformat()}",
            f"- **Confirmed findings:** {len(findings)}",
            "",
            "Each finding below includes a SHA-256 evidence hash and a "
            "replay command so your team can independently verify before "
            "applying the patch.",
            "",
        ]
        for finding in findings:
            lines.extend(
                [
                    f"## {finding.get('finding_id', 'finding')} "
                    f"({finding.get('outcome', 'unknown')})",
                    "",
                    f"- **Agent:** {finding.get('agent_role', 'unknown')}",
                    f"- **Endpoint:** {finding.get('method', '')} "
                    f"{finding.get('url', '')}",
                    f"- **Invariant:** "
                    f"{finding.get('expected_invariant', '')}",
                    f"- **Observed:** "
                    f"{finding.get('observed_behavior', '')[:300]}",
                    f"- **Evidence hash:** "
                    f"`{finding.get('evidence_hash', '')[:32]}...`",
                    "",
                    "**Replay:**",
                    "```bash",
                    finding.get("replay_command", ""),
                    "```",
                    "",
                ]
            )
        report_path = self.base_dir / "EVIDENCE_REPORT.md"
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path

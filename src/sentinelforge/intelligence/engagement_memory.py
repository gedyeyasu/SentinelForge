from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EngagementRecord:
    engagement_id: str
    target: str
    started_at: float
    completed_at: float | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    payloads_used: list[str] = field(default_factory=list)
    techniques_tried: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "finding_count": len(self.findings),
            "payload_count": len(self.payloads_used),
            "techniques": self.techniques_tried,
            "metadata": self.metadata,
        }


class EngagementMemory:
    """Persistent memory across engagements.

    Stores historical scan results, successful payloads,
    and discovered patterns for reuse in future assessments.
    """

    def __init__(self, *, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or Path.home() / ".sentinelforge" / "memory"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._engagements: dict[str, EngagementRecord] = {}
        self._target_history: dict[str, list[str]] = {}
        self._load_data()

    def start_engagement(self, target: str, engagement_id: str = "") -> EngagementRecord:
        import uuid

        if not engagement_id:
            engagement_id = "eng_" + uuid.uuid4().hex[:12]

        record = EngagementRecord(
            engagement_id=engagement_id,
            target=target,
            started_at=time.time(),
        )
        self._engagements[engagement_id] = record

        if target not in self._target_history:
            self._target_history[target] = []
        self._target_history[target].append(engagement_id)

        self._save_data()
        return record

    def complete_engagement(
        self,
        engagement_id: str,
        findings: list[dict[str, Any]] | None = None,
        payloads_used: list[str] | None = None,
        techniques_tried: list[str] | None = None,
    ) -> EngagementRecord | None:
        record = self._engagements.get(engagement_id)
        if record is None:
            return None

        record.completed_at = time.time()
        if findings:
            record.findings = findings
        if payloads_used:
            record.payloads_used = payloads_used
        if techniques_tried:
            record.techniques_tried = techniques_tried

        self._save_data()
        return record

    def get_target_history(self, target: str) -> list[EngagementRecord]:
        engagement_ids = self._target_history.get(target, [])
        return [
            self._engagements[eid]
            for eid in engagement_ids
            if eid in self._engagements
        ]

    def get_successful_payloads(self, target: str) -> list[str]:
        history = self.get_target_history(target)
        payloads: list[str] = []
        for record in history:
            for finding in record.findings:
                if finding.get("outcome") == "success":
                    payload = finding.get("payload", "")
                    if payload and payload not in payloads:
                        payloads.append(payload)
        return payloads

    def get_techniques_for_target(self, target: str) -> list[str]:
        history = self.get_target_history(target)
        techniques: list[str] = []
        for record in history:
            for technique in record.techniques_tried:
                if technique not in techniques:
                    techniques.append(technique)
        return techniques

    def get_common_findings(self, target: str, min_occurrences: int = 2) -> list[dict[str, Any]]:
        history = self.get_target_history(target)
        finding_counts: dict[str, dict[str, Any]] = {}

        for record in history:
            for finding in record.findings:
                key = f"{finding.get('type', '')}:{finding.get('location', '')}"
                if key not in finding_counts:
                    finding_counts[key] = {**finding, "count": 0}
                finding_counts[key]["count"] += 1

        return [
            f for f in finding_counts.values()
            if f["count"] >= min_occurrences
        ]

    def get_stats(self) -> dict[str, Any]:
        total_findings = sum(
            len(r.findings) for r in self._engagements.values()
        )
        completed = sum(
            1 for r in self._engagements.values() if r.completed_at
        )

        return {
            "total_engagements": len(self._engagements),
            "completed": completed,
            "total_findings": total_findings,
            "unique_targets": len(self._target_history),
        }

    def _load_data(self) -> None:
        engagements_file = self._data_dir / "engagements.json"
        if engagements_file.exists():
            try:
                data = json.loads(engagements_file.read_text(encoding="utf-8"))
                for item in data:
                    record = EngagementRecord(**item)
                    self._engagements[record.engagement_id] = record
                    if record.target not in self._target_history:
                        self._target_history[record.target] = []
                    self._target_history[record.target].append(record.engagement_id)
            except Exception:
                logger.debug("Failed to load engagement data")

    def _save_data(self) -> None:
        try:
            engagements_file = self._data_dir / "engagements.json"
            data = [r.to_dict() for r in self._engagements.values()]
            engagements_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            logger.debug("Failed to save engagement data")

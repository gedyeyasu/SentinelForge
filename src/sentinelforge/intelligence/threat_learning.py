from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ThreatPattern:
    pattern_id: str
    category: str
    indicator: str
    confidence: float
    source_cves: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    hit_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "category": self.category,
            "indicator": self.indicator,
            "confidence": self.confidence,
            "source_cves": self.source_cves,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
        }


class ThreatLearner:
    """Extracts threat patterns from CVE data and scan results.

    Learns from historical findings to improve detection accuracy.
    """

    def __init__(self, *, data_dir: Path | None = None) -> None:
        import os

        if data_dir:
            self._data_dir = data_dir
        else:
            try:
                home = Path.home()
                candidate = home / ".sentinelforge" / "threats"
                candidate.parent.mkdir(parents=True, exist_ok=True)
                self._data_dir = candidate
            except (PermissionError, OSError):
                fallback = Path(os.environ.get("SENTINELFORGE_STATE_ROOT", ".sentinelforge")) / "threats"
                if not fallback.is_absolute():
                    fallback = Path.cwd() / fallback
                fallback.mkdir(parents=True, exist_ok=True)
                self._data_dir = fallback
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._patterns: dict[str, ThreatPattern] = {}
        self._load_patterns()

    def learn_from_cve(self, cve_entry: dict[str, Any]) -> list[ThreatPattern]:
        learned: list[ThreatPattern] = []
        cve_id = cve_entry.get("cve_id", "")
        description = cve_entry.get("description", "").lower()
        affected = cve_entry.get("affected_packages", [])

        category = self._classify_description(description)
        if category:
            pattern = self._upsert_pattern(
                category=category,
                indicator=description[:200],
                cve_id=cve_id,
            )
            learned.append(pattern)

        for pkg in affected:
            pattern = self._upsert_pattern(
                category="dependency",
                indicator=pkg,
                cve_id=cve_id,
            )
            learned.append(pattern)

        if cve_entry.get("exploit_available"):
            pattern = self._upsert_pattern(
                category="exploit_available",
                indicator=cve_id,
                cve_id=cve_id,
            )
            learned.append(pattern)

        if cve_entry.get("kev_listed"):
            pattern = self._upsert_pattern(
                category="actively_exploited",
                indicator=cve_id,
                cve_id=cve_id,
            )
            learned.append(pattern)

        self._save_patterns()
        return learned

    def learn_from_scan(
        self,
        scan_result: dict[str, Any],
        repository: str = "",
    ) -> list[ThreatPattern]:
        learned: list[ThreatPattern] = []

        for finding in scan_result.get("findings", []):
            category = finding.get("type", "unknown")
            indicator = finding.get("description", "")[:200]
            pattern = self._upsert_pattern(
                category=category,
                indicator=indicator,
                cve_id="",
            )
            learned.append(pattern)

        self._save_patterns()
        return learned

    def get_patterns(
        self,
        category: str | None = None,
        min_confidence: float = 0.0,
        limit: int = 100,
    ) -> list[ThreatPattern]:
        patterns = list(self._patterns.values())

        if category:
            patterns = [p for p in patterns if p.category == category]

        if min_confidence > 0:
            patterns = [p for p in patterns if p.confidence >= min_confidence]

        patterns.sort(key=lambda p: p.confidence, reverse=True)
        return patterns[:limit]

    def get_pattern_stats(self) -> dict[str, Any]:
        categories: dict[str, int] = {}
        for p in self._patterns.values():
            categories[p.category] = categories.get(p.category, 0) + 1

        return {
            "total_patterns": len(self._patterns),
            "categories": categories,
            "high_confidence": sum(
                1 for p in self._patterns.values() if p.confidence >= 0.8
            ),
        }

    def _classify_description(self, description: str) -> str | None:
        classifications = [
            ("sql_injection", ["sql", "injection", "query"]),
            ("xss", ["cross-site scripting", "xss", "<script"]),
            ("path_traversal", ["path traversal", "directory traversal", "../"]),
            ("command_injection", ["command injection", "os command", "shell injection"]),
            ("authentication_bypass", ["authentication bypass", "auth bypass", "credential"]),
            ("authorization", ["authorization", "permission", "access control", "bola"]),
            ("deserialization", ["deserialization", "pickle", "marshal"]),
            ("ssrf", ["server-side request forgery", "ssrf"]),
            ("race_condition", ["race condition", "race condition", "concurrent"]),
            ("hardcoded_secret", ["hardcoded", "secret", "password", "api key"]),
        ]
        for category, keywords in classifications:
            if any(kw in description for kw in keywords):
                return category
        return None

    def _upsert_pattern(
        self,
        category: str,
        indicator: str,
        cve_id: str,
    ) -> ThreatPattern:
        import hashlib

        pattern_key = f"{category}:{indicator[:50]}"
        pattern_id = hashlib.sha256(pattern_key.encode()).hexdigest()[:16]

        now = time.time()
        if pattern_id in self._patterns:
            existing = self._patterns[pattern_id]
            existing.hit_count += 1
            existing.last_seen = now
            existing.confidence = min(1.0, existing.confidence + 0.05)
            if cve_id and cve_id not in existing.source_cves:
                existing.source_cves.append(cve_id)
            return existing

        pattern = ThreatPattern(
            pattern_id=pattern_id,
            category=category,
            indicator=indicator,
            confidence=0.5,
            source_cves=[cve_id] if cve_id else [],
            first_seen=now,
            last_seen=now,
            hit_count=1,
        )
        self._patterns[pattern_id] = pattern
        return pattern

    def _load_patterns(self) -> None:
        patterns_file = self._data_dir / "patterns.json"
        if patterns_file.exists():
            try:
                data = json.loads(patterns_file.read_text(encoding="utf-8"))
                for item in data:
                    p = ThreatPattern(**item)
                    self._patterns[p.pattern_id] = p
            except Exception:
                logger.debug("Failed to load threat patterns")

    def _save_patterns(self) -> None:
        try:
            patterns_file = self._data_dir / "patterns.json"
            data = [p.to_dict() for p in self._patterns.values()]
            patterns_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            logger.debug("Failed to save threat patterns")

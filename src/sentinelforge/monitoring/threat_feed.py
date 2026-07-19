from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class FeedStatus(StrEnum):
    ACTIVE = "active"
    ERROR = "error"
    STALE = "stale"


@dataclass
class ThreatFeedEntry:
    feed_id: str
    source: str
    title: str
    severity: str
    published_at: float
    url: str = ""
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "source": self.source,
            "title": self.title,
            "severity": self.severity,
            "published_at": self.published_at,
            "url": self.url,
            "description": self.description[:200],
            "cve_ids": self.cve_ids,
        }


class ThreatFeed:
    """Aggregates threat intelligence from multiple feeds.

    Provides a unified interface to access security advisories
    and vulnerability disclosures from various sources.
    """

    FEEDS = {
        "github_advisories": {
            "url": "https://api.github.com/advisories",
            "type": "github",
        },
        "nvd": {
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "type": "nvd",
        },
    }

    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        import os

        if cache_dir:
            self._cache_dir = cache_dir
        else:
            try:
                home = Path.home()
                candidate = home / ".sentinelforge" / "feeds"
                candidate.parent.mkdir(parents=True, exist_ok=True)
                self._cache_dir = candidate
            except (PermissionError, OSError):
                fallback = Path(os.environ.get("SENTINELFORGE_STATE_ROOT", ".sentinelforge")) / "feeds"
                if not fallback.is_absolute():
                    fallback = Path.cwd() / fallback
                fallback.mkdir(parents=True, exist_ok=True)
                self._cache_dir = fallback
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = client or httpx.Client(timeout=15)
        self._entries: list[ThreatFeedEntry] = []
        self._feed_status: dict[str, FeedStatus] = {}
        self._last_updated: dict[str, float] = {}
        self._load_cache()

    def fetch_github_advisories(
        self, per_page: int = 30
    ) -> list[ThreatFeedEntry]:

        entries: list[ThreatFeedEntry] = []
        try:
            response = self._client.get(
                self.FEEDS["github_advisories"]["url"],
                params={"per_page": per_page, "type": "reviewed"},
            )
            response.raise_for_status()
            data = response.json()

            for advisory in data:
                ghsa_id = advisory.get("ghsa_id", "")
                severity = advisory.get("severity", "unknown")
                summary = advisory.get("summary", "")
                published = advisory.get("published_at", "")
                html_url = advisory.get("html_url", "")

                cve_ids = []
                for vuln in advisory.get("vulnerabilities", []):
                    cve_id = vuln.get("vulnerability", {}).get("cve", {}).get("cve_id", "")
                    if cve_id:
                        cve_ids.append(cve_id)

                entry = ThreatFeedEntry(
                    feed_id=ghsa_id,
                    source="github",
                    title=summary[:200],
                    severity=severity,
                    published_at=self._parse_timestamp(published),
                    url=html_url,
                    description=advisory.get("description", "")[:500],
                    cve_ids=cve_ids,
                )
                entries.append(entry)

            self._feed_status["github_advisories"] = FeedStatus.ACTIVE
            self._last_updated["github_advisories"] = time.time()
        except Exception as exc:
            logger.warning("GitHub advisories fetch failed: %s", exc)
            self._feed_status["github_advisories"] = FeedStatus.ERROR

        self._entries.extend(entries)
        self._save_cache()
        return entries

    def get_entries(
        self,
        source: str | None = None,
        severity: str | None = None,
        min_age_hours: int = 24,
        limit: int = 50,
    ) -> list[ThreatFeedEntry]:
        entries = list(self._entries)
        cutoff = time.time() - (min_age_hours * 3600)
        entries = [e for e in entries if e.published_at >= cutoff]

        if source:
            entries = [e for e in entries if e.source == source]
        if severity:
            entries = [e for e in entries if e.severity == severity]

        entries.sort(key=lambda e: e.published_at, reverse=True)
        return entries[:limit]

    def get_feed_status(self) -> dict[str, Any]:
        return {
            source: {
                "status": status.value,
                "last_updated": self._last_updated.get(source, 0),
            }
            for source, status in self._feed_status.items()
        }

    def get_stats(self) -> dict[str, Any]:
        severities: dict[str, int] = {}
        sources: dict[str, int] = {}
        for entry in self._entries:
            severities[entry.severity] = severities.get(entry.severity, 0) + 1
            sources[entry.source] = sources.get(entry.source, 0) + 1

        return {
            "total_entries": len(self._entries),
            "by_severity": severities,
            "by_source": sources,
            "feeds_active": sum(
                1 for s in self._feed_status.values()
                if s == FeedStatus.ACTIVE
            ),
        }

    def _parse_timestamp(self, ts: str) -> float:
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
        except Exception:
            return time.time()

    def _load_cache(self) -> None:
        cache_file = self._cache_dir / "threat_feed.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                for item in data:
                    entry = ThreatFeedEntry(**item)
                    self._entries.append(entry)
            except Exception:
                logger.debug("Failed to load threat feed cache")

    def _save_cache(self) -> None:
        try:
            cache_file = self._cache_dir / "threat_feed.json"
            data = [e.to_dict() for e in self._entries[-500:]]
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            logger.debug("Failed to save threat feed cache")

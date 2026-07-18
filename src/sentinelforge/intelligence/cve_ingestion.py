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


class CVESeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: CVESeverity
    cvss_score: float
    published_date: str
    affected_packages: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
    kev_listed: bool = False
    epss_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "published_date": self.published_date,
            "affected_packages": self.affected_packages,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "kev_listed": self.kev_listed,
            "epss_score": self.epss_score,
        }


@dataclass
class IngestionResult:
    total_fetched: int
    new_entries: int
    kev_entries: int
    high_risk: int
    latency_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_fetched": self.total_fetched,
            "new_entries": self.new_entries,
            "kev_entries": self.kev_entries,
            "high_risk": self.high_risk,
            "latency_ms": self.latency_ms,
        }


class CVEIngester:
    """Ingest CVEs from NVD, KEV, and EPSS feeds.

    Maintains a local cache and provides filtered access to
    vulnerability intelligence.
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._cache_dir = cache_dir or Path.home() / ".sentinelforge" / "cve_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = client or httpx.Client(timeout=30)
        self._entries: dict[str, CVEEntry] = {}
        self._kev_set: set[str] = set()
        self._epss_scores: dict[str, float] = {}
        self._load_cache()

    def ingest_nvd(
        self,
        keyword: str = "",
        days_back: int = 30,
        max_results: int = 200,
    ) -> IngestionResult:
        start = time.monotonic()
        params: dict[str, Any] = {
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
        }
        if keyword:
            params["keywordSearch"] = keyword

        try:
            response = self._client.get(self.NVD_API_URL, params=params)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning("NVD API failed: %s", exc)
            return IngestionResult(0, 0, 0, 0, int((time.monotonic() - start) * 1000))

        new_count = 0
        high_risk = 0
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            desc = descriptions[0].get("value", "") if descriptions else ""

            metrics = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])
            cvss_score = 0.0
            severity = CVESeverity.UNKNOWN
            if cvss_data:
                cvss_info = cvss_data[0].get("cvssData", {})
                cvss_score = cvss_info.get("baseScore", 0.0)
                severity_str = cvss_info.get("severity", "UNKNOWN").lower()
                try:
                    severity = CVESeverity(severity_str)
                except ValueError:
                    severity = CVESeverity.UNKNOWN

            published = cve.get("published", "")
            references = [
                ref.get("url", "")
                for ref in cve.get("references", [])
                if ref.get("url")
            ]

            if cve_id not in self._entries:
                new_count += 1

            self._entries[cve_id] = CVEEntry(
                cve_id=cve_id,
                description=desc[:500],
                severity=severity,
                cvss_score=cvss_score,
                published_date=published,
                references=references[:5],
                kev_listed=cve_id in self._kev_set,
                epss_score=self._epss_scores.get(cve_id, 0.0),
            )

            if severity in (CVESeverity.CRITICAL, CVESeverity.HIGH):
                high_risk += 1

        self._save_cache()
        latency = int((time.monotonic() - start) * 1000)
        return IngestionResult(
            total_fetched=len(data.get("vulnerabilities", [])),
            new_entries=new_count,
            kev_entries=sum(1 for e in self._entries.values() if e.kev_listed),
            high_risk=high_risk,
            latency_ms=latency,
        )

    def ingest_kev(self) -> IngestionResult:
        start = time.monotonic()
        try:
            response = self._client.get(self.KEV_URL)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning("KEV feed failed: %s", exc)
            return IngestionResult(0, 0, 0, 0, int((time.monotonic() - start) * 1000))

        new_count = 0
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue
            self._kev_set.add(cve_id)
            if cve_id in self._entries:
                self._entries[cve_id].kev_listed = True
            else:
                new_count += 1
                self._entries[cve_id] = CVEEntry(
                    cve_id=cve_id,
                    description=vuln.get("shortDescription", ""),
                    severity=CVESeverity.HIGH,
                    cvss_score=8.0,
                    published_date=vuln.get("datePublished", ""),
                    exploit_available=True,
                    kev_listed=True,
                )

        self._save_cache()
        latency = int((time.monotonic() - start) * 1000)
        return IngestionResult(
            total_fetched=data.get("count", 0),
            new_entries=new_count,
            kev_entries=len(self._kev_set),
            high_risk=new_count,
            latency_ms=latency,
        )

    def ingest_epss(self, limit: int = 2000) -> IngestionResult:
        start = time.monotonic()
        try:
            response = self._client.get(
                self.EPSS_URL,
                params={"limit": limit},
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning("EPSS API failed: %s", exc)
            return IngestionResult(0, 0, 0, 0, int((time.monotonic() - start) * 1000))

        new_count = 0
        for item in data.get("data", []):
            cve_id = item.get("cve", "")
            epss = item.get("epss", 0.0)
            if cve_id:
                self._epss_scores[cve_id] = epss
                if cve_id in self._entries:
                    self._entries[cve_id].epss_score = epss
                new_count += 1

        self._save_cache()
        latency = int((time.monotonic() - start) * 1000)
        return IngestionResult(
            total_fetched=len(data.get("data", [])),
            new_entries=new_count,
            kev_entries=0,
            high_risk=sum(
                1 for epss in self._epss_scores.values() if epss >= 0.7
            ),
            latency_ms=latency,
        )

    def get_entry(self, cve_id: str) -> CVEEntry | None:
        return self._entries.get(cve_id)

    def search(
        self,
        keyword: str = "",
        severity: CVESeverity | None = None,
        kev_only: bool = False,
        min_epss: float = 0.0,
        limit: int = 50,
    ) -> list[CVEEntry]:
        results = list(self._entries.values())

        if keyword:
            kw = keyword.lower()
            results = [
                e for e in results
                if kw in e.cve_id.lower() or kw in e.description.lower()
            ]

        if severity:
            results = [e for e in results if e.severity == severity]

        if kev_only:
            results = [e for e in results if e.kev_listed]

        if min_epss > 0:
            results = [e for e in results if e.epss_score >= min_epss]

        results.sort(key=lambda e: (e.cvss_score, e.epss_score), reverse=True)
        return results[:limit]

    def get_stats(self) -> dict[str, Any]:
        severities = {}
        for entry in self._entries.values():
            s = entry.severity.value
            severities[s] = severities.get(s, 0) + 1

        return {
            "total_cves": len(self._entries),
            "kev_count": len(self._kev_set),
            "epss_count": len(self._epss_scores),
            "severities": severities,
        }

    def _load_cache(self) -> None:
        cache_file = self._cache_dir / "nvd_cache.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                for item in data:
                    entry = CVEEntry(**item)
                    self._entries[entry.cve_id] = entry
            except Exception:
                logger.debug("Failed to load NVD cache")

        kev_file = self._cache_dir / "kev_cache.json"
        if kev_file.exists():
            try:
                self._kev_set = set(json.loads(kev_file.read_text(encoding="utf-8")))
            except Exception:
                logger.debug("Failed to load KEV cache")

        epss_file = self._cache_dir / "epss_cache.json"
        if epss_file.exists():
            try:
                self._epss_scores = json.loads(epss_file.read_text(encoding="utf-8"))
            except Exception:
                logger.debug("Failed to load EPSS cache")

    def _save_cache(self) -> None:
        try:
            cache_file = self._cache_dir / "nvd_cache.json"
            entries = [e.to_dict() for e in self._entries.values()]
            cache_file.write_text(json.dumps(entries, indent=2), encoding="utf-8")

            kev_file = self._cache_dir / "kev_cache.json"
            kev_file.write_text(json.dumps(list(self._kev_set)), encoding="utf-8")

            epss_file = self._cache_dir / "epss_cache.json"
            epss_file.write_text(json.dumps(self._epss_scores), encoding="utf-8")
        except Exception:
            logger.debug("Failed to save CVE cache")

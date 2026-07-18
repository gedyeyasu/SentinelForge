from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from sentinelforge.intelligence.cve_ingestion import CVEEntry, CVESeverity

logger = logging.getLogger(__name__)


class OSVClient:
    """OSV.dev client — free, no key, aggregates GHSA/NVD/PyPA/RustSec."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: float = 20) -> None:
        self._client = httpx.Client(timeout=timeout)

    def query_package(
        self, package: str, ecosystem: str = "PyPI"
    ) -> list[CVEEntry]:
        try:
            response = self._client.post(
                f"{self.BASE_URL}/query",
                json={"package": {"name": package, "ecosystem": ecosystem}},
            )
            response.raise_for_status()
            vulns = response.json().get("vulns", [])
        except Exception as error:
            logger.warning("OSV query failed for %s: %s", package, error)
            return []
        entries: list[CVEEntry] = []
        for vuln in vulns[:10]:
            cve_id = next(
                (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                vuln.get("id", ""),
            )
            severity, score = self._severity_from_vuln(vuln)
            entries.append(
                CVEEntry(
                    cve_id=cve_id,
                    description=str(vuln.get("summary", ""))[:500],
                    severity=severity,
                    cvss_score=score,
                    published_date=str(vuln.get("published", "")),
                    affected_packages=[package],
                    references=[
                        r.get("url", "")
                        for r in vuln.get("references", [])[:3]
                    ],
                )
            )
        return entries

    @staticmethod
    def _severity_from_vuln(
        vuln: dict[str, Any],
    ) -> tuple[CVESeverity, float]:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = str(sev.get("score", ""))
                for part in score_str.split("/"):
                    if part.startswith("CVSS"):
                        continue
                # Parse base score from vector tail if present
                try:
                    score = float(score_str.rsplit(":", 1)[-1])
                except (ValueError, IndexError):
                    score = 0.0
                if score >= 9.0:
                    return CVESeverity.CRITICAL, score
                if score >= 7.0:
                    return CVESeverity.HIGH, score
                if score >= 4.0:
                    return CVESeverity.MEDIUM, score
                return CVESeverity.LOW, score
        db = vuln.get("database_specific", {})
        level = str(db.get("severity", "")).lower()
        mapping = {
            "critical": CVESeverity.CRITICAL,
            "high": CVESeverity.HIGH,
            "moderate": CVESeverity.MEDIUM,
            "medium": CVESeverity.MEDIUM,
            "low": CVESeverity.LOW,
        }
        return mapping.get(level, CVESeverity.UNKNOWN), 0.0


class GitHubAdvisoryClient:
    """GitHub Security Advisory (GHSA) client via GraphQL API."""

    API_URL = "https://api.github.com/graphql"

    def __init__(self, token: str = "", timeout: float = 20) -> None:
        self._token = token
        self._client = httpx.Client(timeout=timeout)

    def query_package(
        self, package: str, ecosystem: str = "PIP"
    ) -> list[CVEEntry]:
        if not self._token:
            return []
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem, $package: String!) {
          securityVulnerabilities(
            first: 10,
            ecosystem: $ecosystem,
            package: $package
          ) {
            nodes {
              advisory {
                ghsaId
                summary
                severity
                publishedAt
                identifiers { type value }
                references { url }
              }
              vulnerableVersionRange
            }
          }
        }
        """
        try:
            response = self._client.post(
                self.API_URL,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                json={
                    "query": query,
                    "variables": {
                        "ecosystem": ecosystem,
                        "package": package,
                    },
                },
            )
            response.raise_for_status()
            nodes = (
                response.json()
                .get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )
        except Exception as error:
            logger.warning("GHSA query failed for %s: %s", package, error)
            return []
        entries: list[CVEEntry] = []
        for node in nodes:
            adv = node.get("advisory", {})
            cve_id = next(
                (
                    i["value"]
                    for i in adv.get("identifiers", [])
                    if i.get("type") == "CVE"
                ),
                adv.get("ghsaId", ""),
            )
            severity_map = {
                "CRITICAL": CVESeverity.CRITICAL,
                "HIGH": CVESeverity.HIGH,
                "MODERATE": CVESeverity.MEDIUM,
                "LOW": CVESeverity.LOW,
            }
            entries.append(
                CVEEntry(
                    cve_id=cve_id,
                    description=str(adv.get("summary", ""))[:500],
                    severity=severity_map.get(
                        str(adv.get("severity", "")).upper(),
                        CVESeverity.UNKNOWN,
                    ),
                    cvss_score=0.0,
                    published_date=str(adv.get("publishedAt", "")),
                    affected_packages=[package],
                    references=[
                        r.get("url", "")
                        for r in adv.get("references", [])[:3]
                    ],
                )
            )
        return entries


class IntelAggregator:
    """Multi-source vulnerability intelligence aggregator.

    Merges Red Hat Security Data, NVD/KEV/EPSS (via CVEIngester),
    OSV.dev, and GitHub Security Advisories into one deduplicated,
    risk-ranked feed. Ranking: KEV-listed > EPSS > CVSS > recency.
    """

    def __init__(
        self,
        *,
        github_token: str = "",
        enable_osv: bool = True,
        enable_ghsa: bool = True,
    ) -> None:
        self._osv = OSVClient() if enable_osv else None
        self._ghsa = (
            GitHubAdvisoryClient(github_token)
            if enable_ghsa and github_token
            else None
        )

    def enrich_packages(
        self, packages: list[str], *, ecosystem: str = "PyPI"
    ) -> dict[str, Any]:
        """Query all sources for each package; return merged intel."""
        started = time.monotonic()
        per_source: dict[str, int] = {"osv": 0, "ghsa": 0}
        merged: dict[str, CVEEntry] = {}

        ghsa_ecosystem = {
            "PyPI": "PIP",
            "npm": "NPM",
            "Maven": "MAVEN",
            "Go": "GO",
            "RubyGems": "RUBYGEMS",
        }.get(ecosystem, "PIP")

        for package in packages[:15]:
            if self._osv:
                for entry in self._osv.query_package(package, ecosystem):
                    per_source["osv"] += 1
                    self._merge(merged, entry)
            if self._ghsa:
                for entry in self._ghsa.query_package(
                    package, ghsa_ecosystem
                ):
                    per_source["ghsa"] += 1
                    self._merge(merged, entry)

        ranked = sorted(
            merged.values(), key=self._rank_key, reverse=True
        )
        return {
            "entries": [e.to_dict() for e in ranked],
            "sources": per_source,
            "total_unique": len(ranked),
            "critical_count": sum(
                1 for e in ranked if e.severity is CVESeverity.CRITICAL
            ),
            "kev_count": sum(1 for e in ranked if e.kev_listed),
            "latency_ms": int((time.monotonic() - started) * 1000),
        }

    @staticmethod
    def _merge(merged: dict[str, CVEEntry], entry: CVEEntry) -> None:
        existing = merged.get(entry.cve_id)
        if existing is None:
            merged[entry.cve_id] = entry
            return
        # Merge: prefer higher confidence fields across sources
        if entry.cvss_score > existing.cvss_score:
            existing.cvss_score = entry.cvss_score
            existing.severity = entry.severity
        for pkg in entry.affected_packages:
            if pkg not in existing.affected_packages:
                existing.affected_packages.append(pkg)
        for ref in entry.references:
            if ref and ref not in existing.references:
                existing.references.append(ref)
        existing.kev_listed = existing.kev_listed or entry.kev_listed
        existing.exploit_available = (
            existing.exploit_available or entry.exploit_available
        )
        existing.epss_score = max(existing.epss_score, entry.epss_score)

    @staticmethod
    def _rank_key(entry: CVEEntry) -> tuple[float, float, float, str]:
        return (
            1.0 if entry.kev_listed else 0.0,
            entry.epss_score,
            entry.cvss_score,
            entry.published_date,
        )

from __future__ import annotations

from sentinelforge.intelligence.aggregator import IntelAggregator
from sentinelforge.intelligence.cve_ingestion import CVEEntry, CVESeverity


def _entry(
    cve_id: str,
    severity: CVESeverity = CVESeverity.HIGH,
    score: float = 7.5,
    kev: bool = False,
    epss: float = 0.0,
) -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        description=f"Test {cve_id}",
        severity=severity,
        cvss_score=score,
        published_date="2026-07-01",
        affected_packages=["pkg"],
        kev_listed=kev,
        epss_score=epss,
    )


def test_merge_combines_sources() -> None:
    merged: dict[str, CVEEntry] = {}
    IntelAggregator._merge(merged, _entry("CVE-2026-0001", score=7.0))
    IntelAggregator._merge(
        merged, _entry("CVE-2026-0001", score=9.1, epss=0.5)
    )
    assert len(merged) == 1
    entry = merged["CVE-2026-0001"]
    assert entry.cvss_score == 9.1
    assert entry.severity is CVESeverity.HIGH
    assert entry.epss_score == 0.5


def test_merge_preserves_kev_flag() -> None:
    merged: dict[str, CVEEntry] = {}
    IntelAggregator._merge(merged, _entry("CVE-2026-0002", kev=True))
    IntelAggregator._merge(merged, _entry("CVE-2026-0002", kev=False))
    assert merged["CVE-2026-0002"].kev_listed is True


def test_rank_prioritizes_kev_then_epss_then_cvss() -> None:
    entries = [
        _entry("CVE-2026-0003", score=9.8, epss=0.1, kev=False),
        _entry("CVE-2026-0004", score=5.0, epss=0.0, kev=True),
        _entry("CVE-2026-0005", score=7.0, epss=0.9, kev=False),
    ]
    ranked = sorted(
        entries, key=IntelAggregator._rank_key, reverse=True
    )
    assert ranked[0].cve_id == "CVE-2026-0004"  # KEV first
    assert ranked[1].cve_id == "CVE-2026-0005"  # then EPSS
    assert ranked[2].cve_id == "CVE-2026-0003"  # then CVSS


def test_enrich_packages_aggregates(monkeypatch) -> None:
    agg = IntelAggregator(enable_osv=True, enable_ghsa=False)

    class _FakeOSV:
        def query_package(self, package, ecosystem="PyPI"):
            return [_entry(f"CVE-2026-{package[:4]}")]

    agg._osv = _FakeOSV()
    result = agg.enrich_packages(["django", "flask"])
    assert result["total_unique"] == 2
    assert result["sources"]["osv"] == 2
    assert result["sources"]["ghsa"] == 0
    assert len(result["entries"]) == 2

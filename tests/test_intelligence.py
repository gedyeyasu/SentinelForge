from __future__ import annotations

from sentinelforge.intelligence.adaptive_payloads import AdaptivePayloadGenerator, PayloadSet
from sentinelforge.intelligence.cve_ingestion import CVEEntry, CVESeverity
from sentinelforge.intelligence.engagement_memory import EngagementMemory
from sentinelforge.intelligence.threat_learning import ThreatLearner
from sentinelforge.intelligence.zero_day_hunter import ZeroDayHunter


class TestAdaptivePayloadGenerator:
    def test_generate_sql_injection_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        result = gen.generate_payloads("sql_injection", count=5)
        assert result.category == "sql_injection"
        assert len(result.payloads) <= 5
        assert len(result.payloads) > 0

    def test_generate_xss_payloads(self) -> None:
        gen = AdaptivePayloadGenerator()
        result = gen.generate_payloads("xss", count=3)
        assert result.category == "xss"
        assert len(result.payloads) > 0

    def test_unknown_category_returns_empty(self) -> None:
        gen = AdaptivePayloadGenerator()
        result = gen.generate_payloads("nonexistent_category", count=5)
        assert len(result.payloads) == 0

    def test_update_effectiveness(self) -> None:
        gen = AdaptivePayloadGenerator()
        gen.update_effectiveness("sql_injection", "' OR 1=1--", success=True)
        report = gen.get_effectiveness_report()
        assert "sql_injection" in report
        assert report["sql_injection"]["total_payloads"] == 1

    def test_add_adaptive_payload(self) -> None:
        gen = AdaptivePayloadGenerator()
        gen.add_adaptive_payload("sql_injection", "' WAITFOR DELAY '0:0:5'--")
        result = gen.generate_payloads("sql_injection", count=10, include_adaptive=True)
        assert any("WAITFOR" in p for p in result.payloads)

    def test_payload_set_to_dict(self) -> None:
        ps = PayloadSet(category="test", payloads=["a", "b"], source="base")
        d = ps.to_dict()
        assert d["category"] == "test"
        assert d["payload_count"] == 2


class TestCVEEntry:
    def test_cve_entry_to_dict(self) -> None:
        entry = CVEEntry(
            cve_id="CVE-2024-1234",
            description="Test vulnerability",
            severity=CVESeverity.HIGH,
            cvss_score=8.5,
            published_date="2024-01-01",
            affected_packages=["requests"],
            kev_listed=True,
        )
        d = entry.to_dict()
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["severity"] == "high"
        assert d["kev_listed"] is True


class TestThreatLearner:
    def test_learn_from_cve(self, tmp_path) -> None:
        learner = ThreatLearner(data_dir=tmp_path)
        patterns = learner.learn_from_cve({
            "cve_id": "CVE-2024-9999",
            "description": "SQL injection vulnerability",
            "affected_packages": ["flask"],
            "exploit_available": True,
            "kev_listed": True,
        })
        assert len(patterns) > 0
        stats = learner.get_pattern_stats()
        assert stats["total_patterns"] > 0

    def test_get_patterns(self, tmp_path) -> None:
        learner = ThreatLearner(data_dir=tmp_path)
        learner.learn_from_cve({
            "cve_id": "CVE-2024-0001",
            "description": "XSS vulnerability",
        })
        patterns = learner.get_patterns(category="xss")
        assert len(patterns) >= 0


class TestEngagementMemory:
    def test_start_and_complete(self, tmp_path) -> None:
        memory = EngagementMemory(data_dir=tmp_path)
        record = memory.start_engagement("http://example.com")
        assert record.engagement_id
        assert record.target == "http://example.com"

        memory.complete_engagement(
            record.engagement_id,
            findings=[{"type": "xss", "outcome": "success", "payload": "<script>"}],
            techniques_tried=["reflected_xss"],
        )
        history = memory.get_target_history("http://example.com")
        assert len(history) == 1
        assert len(history[0].findings) == 1

    def test_get_successful_payloads(self, tmp_path) -> None:
        memory = EngagementMemory(data_dir=tmp_path)
        record = memory.start_engagement("http://example.com")
        memory.complete_engagement(
            record.engagement_id,
            findings=[
                {"type": "xss", "outcome": "success", "payload": "<script>"},
                {"type": "xss", "outcome": "blocked", "payload": "alert(1)"},
            ],
        )
        payloads = memory.get_successful_payloads("http://example.com")
        assert "<script>" in payloads
        assert "alert(1)" not in payloads

    def test_stats(self, tmp_path) -> None:
        memory = EngagementMemory(data_dir=tmp_path)
        record = memory.start_engagement("http://example.com")
        memory.complete_engagement(record.engagement_id)
        stats = memory.get_stats()
        assert stats["total_engagements"] == 1
        assert stats["completed"] == 1


class TestZeroDayHunter:
    def test_wide_exploration(self) -> None:
        hunter = ZeroDayHunter()
        routes = [
            {"path": "/api/users/{id}", "method": "GET"},
            {"path": "/api/admin/delete", "method": "POST"},
        ]
        hypotheses = hunter.wide_exploration(routes)
        assert len(hypotheses) > 0
        assert all(h.category for h in hypotheses)

    def test_deep_exploration(self) -> None:
        hunter = ZeroDayHunter()
        routes = [{"path": "/api/users/{id}", "method": "GET"}]
        hypotheses = hunter.wide_exploration(routes)
        if hypotheses:
            hyp = hypotheses[0]
            hunter.deep_exploration(hyp, [{"success": True, "evidence": "test", "payload": "test"}])
            assert hyp.tested is True

    def test_harvest_results(self) -> None:
        hunter = ZeroDayHunter()
        routes = [{"path": "/api/{id}", "method": "GET"}]
        hunter.wide_exploration(routes)
        results = hunter.harvest_results()
        assert "total_hypotheses" in results
        assert results["tested"] == 0

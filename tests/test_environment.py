from __future__ import annotations

from sentinelforge.environment import (
    EnvironmentClassification,
    EnvironmentDetector,
    EnvironmentTier,
)


class TestEnvironmentDetector:
    def test_localhost_is_development(self) -> None:
        detector = EnvironmentDetector()
        classification = detector.detect("http://localhost:8000")
        assert classification.tier == EnvironmentTier.DEVELOPMENT
        assert classification.confidence > 0

    def test_127_0_0_1_is_development(self) -> None:
        detector = EnvironmentDetector()
        classification = detector.detect("http://127.0.0.1:3000")
        assert classification.tier == EnvironmentTier.DEVELOPMENT

    def test_staging_host(self) -> None:
        detector = EnvironmentDetector()
        classification = detector.detect("https://staging.example.com")
        assert classification.tier in (
            EnvironmentTier.DEVELOPMENT,
            EnvironmentTier.STAGING,
        )
        assert any("staging" in s for s in classification.signals)

    def test_is_production_false_for_localhost(self) -> None:
        detector = EnvironmentDetector()
        assert not detector.is_production("http://localhost:8000")

    def test_classification_to_dict(self) -> None:
        classification = EnvironmentClassification(
            tier=EnvironmentTier.DEVELOPMENT,
            confidence=0.9,
            signals=["localhost"],
            url="http://localhost:8000",
        )
        d = classification.to_dict()
        assert d["tier"] == "development"
        assert d["confidence"] == 0.9
        assert "localhost" in d["signals"]

    def test_scan_codebase_for_env_hints(self, tmp_path) -> None:
        (tmp_path / ".env").write_text("DEBUG=True\n")
        (tmp_path / ".env.production").write_text("DATABASE_URL=prod\n")

        detector = EnvironmentDetector()
        hints = detector.scan_codebase_for_env_hints(str(tmp_path))
        assert len(hints["env_files_found"]) == 2

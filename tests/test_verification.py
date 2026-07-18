from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from sentinelforge.verification import (
    OwnershipStatus,
    OwnershipVerificationService,
    VerificationMethod,
    VerificationOutcome,
)


class TestOwnershipVerificationService:
    def test_file_challenge_lifecycle(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        target = str(tmp_path)

        challenge = service.start_verification(target, VerificationMethod.FILE)
        assert challenge.method == VerificationMethod.FILE
        assert challenge.status == OwnershipStatus.PENDING
        assert "file_path" in challenge.metadata

        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.NOT_OWNED

        file_path = Path(challenge.metadata["file_path"])
        file_path.write_text(challenge.token, encoding="utf-8")

        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.OWNED
        assert service.is_target_verified(target)

    def test_http_challenge_not_available(self) -> None:
        service = OwnershipVerificationService()
        challenge = service.start_verification(
            "http://localhost:99999", VerificationMethod.HTTP_ENDPOINT
        )
        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.NOT_OWNED

    def test_api_challenge_not_available(self) -> None:
        service = OwnershipVerificationService()
        challenge = service.start_verification(
            "http://localhost:99999", VerificationMethod.API_ENDPOINT
        )
        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.NOT_OWNED

    def test_dns_challenge_not_available(self) -> None:
        service = OwnershipVerificationService()
        challenge = service.start_verification(
            "nonexistent.invalid", VerificationMethod.DNS
        )
        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.NOT_OWNED

    def test_nonexistent_challenge_returns_unverifiable(self) -> None:
        service = OwnershipVerificationService()
        result = service.check_verification("nonexistent_challenge_id")
        assert result.outcome == VerificationOutcome.UNVERIFIABLE

    def test_already_verified_returns_immediately(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        target = str(tmp_path)

        challenge = service.start_verification(target, VerificationMethod.FILE)
        file_path = Path(challenge.metadata["file_path"])
        file_path.write_text(challenge.token, encoding="utf-8")
        service.check_verification(challenge.challenge_id)
        assert service.is_target_verified(target)

        challenge2 = service.start_verification(target, VerificationMethod.FILE)
        assert challenge2.status == OwnershipStatus.VERIFIED

    def test_revoke_verification(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        target = str(tmp_path)

        challenge = service.start_verification(target, VerificationMethod.FILE)
        file_path = Path(challenge.metadata["file_path"])
        file_path.write_text(challenge.token, encoding="utf-8")
        service.check_verification(challenge.challenge_id)
        assert service.is_target_verified(target)

        assert service.revoke_verification(target)
        assert not service.is_target_verified(target)

    def test_expired_challenge(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService(ttl_seconds=-1)
        target = str(tmp_path)

        challenge = service.start_verification(target, VerificationMethod.FILE)
        result = service.check_verification(challenge.challenge_id)
        assert result.outcome == VerificationOutcome.UNVERIFIABLE
        assert "expired" in result.message.lower()

    def test_list_challenges(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        target = str(tmp_path)
        service.start_verification(target, VerificationMethod.FILE)
        service.start_verification(target, VerificationMethod.DNS)

        challenges = service.list_challenges(target)
        assert len(challenges) == 2

    def test_max_challenges_per_target(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        target = str(tmp_path)
        for _ in range(5):
            service.start_verification(target, VerificationMethod.FILE)
        with pytest.raises(ValueError, match="Too many active challenges"):
            service.start_verification(target, VerificationMethod.FILE)

    def test_to_dict(self, tmp_path: Path) -> None:
        service = OwnershipVerificationService()
        challenge = service.start_verification(
            str(tmp_path), VerificationMethod.FILE
        )
        d = challenge.to_dict()
        assert "challenge_id" in d
        assert "method" in d
        assert d["method"] == "file"

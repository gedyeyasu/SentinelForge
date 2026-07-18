from __future__ import annotations

import logging
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx

from sentinelforge.domain import VerificationReport, VerificationStatus

logger = logging.getLogger(__name__)


def verify_python_project(project_root: Path, timeout_seconds: int = 90) -> VerificationReport:
    command = (sys.executable, "-m", "pytest")
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        passed = result.returncode == 0
        return VerificationReport(
            status=VerificationStatus.PASSED if passed else VerificationStatus.FAILED,
            command=command,
            exit_code=result.returncode,
            duration_ms=duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            checks={"repository_tests": passed, "security_regression": passed},
        )
    except subprocess.TimeoutExpired as error:
        duration_ms = int((time.monotonic() - started) * 1000)
        return VerificationReport(
            status=VerificationStatus.FAILED,
            command=command,
            exit_code=124,
            duration_ms=duration_ms,
            stdout=(error.stdout or "") if isinstance(error.stdout, str) else "",
            stderr="Verification timed out",
            checks={"repository_tests": False, "security_regression": False},
        )


class VerificationMethod(StrEnum):
    FILE = "file"
    DNS = "dns"
    HTTP_ENDPOINT = "http_endpoint"
    API_ENDPOINT = "api_endpoint"


class OwnershipStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class VerificationOutcome(StrEnum):
    OWNED = "owned"
    NOT_OWNED = "not_owned"
    UNVERIFIABLE = "unverifiable"


@dataclass
class ChallengeRecord:
    challenge_id: str
    method: VerificationMethod
    target: str
    token: str
    created_at: float
    expires_at: float
    status: OwnershipStatus = OwnershipStatus.PENDING
    verified_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "method": self.method.value,
            "target": self.target,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "verified_at": self.verified_at,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class VerificationResult:
    outcome: VerificationOutcome
    method: VerificationMethod
    target: str
    challenge_id: str
    message: str
    latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "method": self.method.value,
            "target": self.target,
            "challenge_id": self.challenge_id,
            "message": self.message,
            "latency_ms": self.latency_ms,
        }


class OwnershipVerificationService:
    """Enterprise-style ownership verification gate.

    Implements challenge-response verification inspired by:
    - Let's Encrypt ACME (HTTP-01, DNS-01)
    - AWS Security Agent (HTTP route + DNS TXT)
    - Asterion/Argos (HTTP/DNS with expiry)

    Verifies caller owns the target before allowing pentest operations.
    """

    CHALLENGE_TTL_SECONDS = 48 * 3600  # 48 hours like Asterion
    MAX_CHALLENGES_PER_TARGET = 5

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self._client = client or httpx.Client(timeout=10, follow_redirects=False)
        self._ttl = ttl_seconds or self.CHALLENGE_TTL_SECONDS
        self._challenges: dict[str, ChallengeRecord] = {}
        self._verified_targets: set[str] = set()

    def get_verified_targets(self) -> set[str]:
        return set(self._verified_targets)

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        challenge = self._challenges.get(challenge_id)
        if challenge and challenge.is_expired:
            challenge.status = OwnershipStatus.EXPIRED
        return challenge

    def list_challenges(self, target: str | None = None) -> list[ChallengeRecord]:
        challenges = list(self._challenges.values())
        if target:
            challenges = [c for c in challenges if c.target == target]
        return challenges

    def start_verification(
        self, target: str, method: VerificationMethod
    ) -> ChallengeRecord:
        if target in self._verified_targets:
            existing = [
                c
                for c in self._challenges.values()
                if c.target == target
                and c.status == OwnershipStatus.VERIFIED
            ]
            if existing:
                return existing[0]

        active = [
            c
            for c in self._challenges.values()
            if c.target == target
            and c.status == OwnershipStatus.PENDING
            and not c.is_expired
        ]
        if len(active) >= self.MAX_CHALLENGES_PER_TARGET:
            raise ValueError(
                f"Too many active challenges for {target}. "
                f"Max: {self.MAX_CHALLENGES_PER_TARGET}"
            )

        challenge_id = "sf_ch_" + secrets.token_hex(12)
        token = secrets.token_hex(16)
        now = time.time()

        record = ChallengeRecord(
            challenge_id=challenge_id,
            method=method,
            target=target,
            token=token,
            created_at=now,
            expires_at=now + self._ttl,
            metadata=self._prepare_metadata(target, method, token),
        )
        self._challenges[challenge_id] = record
        return record

    def check_verification(self, challenge_id: str) -> VerificationResult:
        record = self._challenges.get(challenge_id)
        if record is None:
            return VerificationResult(
                outcome=VerificationOutcome.UNVERIFIABLE,
                method=VerificationMethod.FILE,
                target="",
                challenge_id=challenge_id,
                message="Challenge not found",
            )

        if record.is_expired:
            record.status = OwnershipStatus.EXPIRED
            return VerificationResult(
                outcome=VerificationOutcome.UNVERIFIABLE,
                method=record.method,
                target=record.target,
                challenge_id=challenge_id,
                message="Challenge has expired",
            )

        if record.status == OwnershipStatus.VERIFIED:
            return VerificationResult(
                outcome=VerificationOutcome.OWNED,
                method=record.method,
                target=record.target,
                challenge_id=challenge_id,
                message="Already verified",
            )

        start = time.monotonic()
        verified = self._verify(record)
        latency = int((time.monotonic() - start) * 1000)

        if verified:
            record.status = OwnershipStatus.VERIFIED
            record.verified_at = time.time()
            self._verified_targets.add(record.target)
            return VerificationResult(
                outcome=VerificationOutcome.OWNED,
                method=record.method,
                target=record.target,
                challenge_id=challenge_id,
                message="Ownership verified",
                latency_ms=latency,
            )
        else:
            record.status = OwnershipStatus.FAILED
            return VerificationResult(
                outcome=VerificationOutcome.NOT_OWNED,
                method=record.method,
                target=record.target,
                challenge_id=challenge_id,
                message="Ownership proof failed or not yet placed",
                latency_ms=latency,
            )

    def is_target_verified(self, target: str) -> bool:
        return target in self._verified_targets

    def revoke_verification(self, target: str) -> bool:
        removed = target in self._verified_targets
        self._verified_targets.discard(target)
        for record in self._challenges.values():
            if record.target == target:
                record.status = OwnershipStatus.FAILED
        return removed

    def _prepare_metadata(
        self, target: str, method: VerificationMethod, token: str
    ) -> dict[str, Any]:
        if method == VerificationMethod.FILE:
            return {
                "file_path": f"{target}/.sentinelforge-ownership",
                "expected_content": token,
                "instruction": (
                    f"Create .sentinelforge-ownership in {target} "
                    f"containing: {token}"
                ),
            }
        elif method == VerificationMethod.DNS:
            return {
                "record_type": "TXT",
                "record_name": f"_sentinelforge-verify.{target}",
                "record_value": f"sentinelforge-verify={token}",
                "instruction": (
                    f"Add TXT record: _sentinelforge-verify.{target} "
                    f'= "sentinelforge-verify={token}"'
                ),
            }
        elif method == VerificationMethod.HTTP_ENDPOINT:
            path = "/.sentinelforge-ownership"
            return {
                "url": f"{target.rstrip('/')}{path}",
                "expected_content": token,
                "instruction": (
                    f"Serve token at {target.rstrip('/')}{path} "
                    f"with exact content: {token}"
                ),
            }
        elif method == VerificationMethod.API_ENDPOINT:
            return {
                "endpoint": f"{target.rstrip('/')}/api/sentinelforge/verify",
                "expected_param": "challenge_token",
                "token": token,
                "instruction": (
                    f"Create GET endpoint at "
                    f"{target.rstrip('/')}/api/sentinelforge/verify "
                    f"that returns the challenge token when called with "
                    f"?token={token}"
                ),
            }
        return {}

    def _verify(self, record: ChallengeRecord) -> bool:
        if record.method == VerificationMethod.FILE:
            return self._verify_file(record)
        elif record.method == VerificationMethod.DNS:
            return self._verify_dns(record)
        elif record.method == VerificationMethod.HTTP_ENDPOINT:
            return self._verify_http(record)
        elif record.method == VerificationMethod.API_ENDPOINT:
            return self._verify_api(record)
        return False

    def _verify_file(self, record: ChallengeRecord) -> bool:
        import pathlib

        file_path = record.metadata.get("file_path", "")
        if not file_path:
            return False
        path = pathlib.Path(file_path)
        if not path.exists():
            return False
        try:
            content = path.read_text(encoding="utf-8").strip()
            return content == record.token
        except OSError:
            return False

    def _verify_dns(self, record: ChallengeRecord) -> bool:
        record_name = record.metadata.get("record_name", "")
        if not record_name:
            return False
        try:
            result = subprocess.run(
                ["dig", "TXT", record_name, "+short"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            expected = f"sentinelforge-verify={record.token}"
            return expected in result.stdout
        except Exception:
            return False

    def _verify_http(self, record: ChallengeRecord) -> bool:
        url = record.metadata.get("url", "")
        if not url:
            return False
        try:
            response = self._client.get(url, timeout=5)
            return response.text.strip() == record.token
        except Exception:
            return False

    def _verify_api(self, record: ChallengeRecord) -> bool:
        endpoint = record.metadata.get("endpoint", "")
        if not endpoint:
            return False
        try:
            response = self._client.get(
                endpoint,
                params={"token": record.token},
                timeout=5,
            )
            if response.status_code == 200:
                body = response.json()
                return body.get("verified") is True or body.get("token") == record.token
            return False
        except Exception:
            return False

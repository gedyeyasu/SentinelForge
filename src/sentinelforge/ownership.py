from __future__ import annotations

import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass(frozen=True)
class OwnershipChallenge:
    challenge_type: str
    token: str
    instruction: str
    verification_command: str

    def to_dict(self) -> dict[str, str]:
        return {
            "challenge_type": self.challenge_type,
            "token": self.token,
            "instruction": self.instruction,
            "verification_command": self.verification_command,
        }


class OwnershipProver:
    """Verify ownership of a target before allowing pentest operations.

    Supports DNS TXT record verification and file-based challenge-response.
    """

    def __init__(self, *, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=10)

    def create_file_challenge(self, target_dir: Path) -> OwnershipChallenge:
        token = secrets.token_hex(16)
        marker_file = target_dir / ".sentinelforge_ownership"
        marker_file.write_text(token, encoding="utf-8")
        return OwnershipChallenge(
            challenge_type="file",
            token=token,
            instruction=(
                f"A challenge file has been placed at {marker_file}. "
                f"To prove ownership, confirm the token matches."
            ),
            verification_command=f"cat {marker_file}",
        )

    def verify_file_challenge(
        self, target_dir: Path, expected_token: str
    ) -> bool:
        marker_file = target_dir / ".sentinelforge_ownership"
        if not marker_file.exists():
            return False
        actual = marker_file.read_text(encoding="utf-8").strip()
        return actual == expected_token

    def create_dns_challenge(self, domain: str) -> OwnershipChallenge:
        token = secrets.token_hex(16)
        return OwnershipChallenge(
            challenge_type="dns",
            token=token,
            instruction=(
                f"Add a TXT record to {domain} with the value: "
                f"sentinelforge-verify={token}"
            ),
            verification_command=f"dig TXT {domain} +short | grep sentinelforge-verify={token}",
        )

    def verify_dns_challenge(self, domain: str, expected_token: str) -> bool:
        try:
            result = subprocess.run(
                ["dig", "TXT", domain, "+short"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return f"sentinelforge-verify={expected_token}" in result.stdout
        except Exception:
            return False

    def create_http_challenge(self, target_url: str) -> OwnershipChallenge:
        token = secrets.token_hex(16)
        return OwnershipChallenge(
            challenge_type="http",
            token=token,
            instruction=(
                f"Serve the token at {target_url.rstrip('/')}/.sentinelforge-ownership "
                f"with content: {token}"
            ),
            verification_command=(
                f"curl -s {target_url.rstrip('/')}/.sentinelforge-ownership"
            ),
        )

    def verify_http_challenge(self, target_url: str, expected_token: str) -> bool:
        try:
            url = f"{target_url.rstrip('/')}/.sentinelforge-ownership"
            response = self._client.get(url, timeout=5)
            return response.text.strip() == expected_token
        except Exception:
            return False

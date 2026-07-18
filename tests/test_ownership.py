from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinelforge.ownership import OwnershipChallenge, OwnershipProver


def test_ownership_challenge_to_dict() -> None:
    challenge = OwnershipChallenge(
        challenge_type="file",
        token="abc123",
        instruction="Place file",
        verification_command="cat .sentinelforge_ownership",
    )
    d = challenge.to_dict()
    assert d["challenge_type"] == "file"
    assert d["token"] == "abc123"
    assert d["instruction"] == "Place file"


def test_create_file_challenge(tmp_path: Path) -> None:
    prover = OwnershipProver()
    challenge = prover.create_file_challenge(tmp_path)

    assert challenge.challenge_type == "file"
    assert len(challenge.token) == 32
    marker = tmp_path / ".sentinelforge_ownership"
    assert marker.exists()
    assert marker.read_text() == challenge.token


def test_verify_file_challenge_success(tmp_path: Path) -> None:
    prover = OwnershipProver()
    challenge = prover.create_file_challenge(tmp_path)
    assert prover.verify_file_challenge(tmp_path, challenge.token) is True


def test_verify_file_challenge_wrong_token(tmp_path: Path) -> None:
    prover = OwnershipProver()
    prover.create_file_challenge(tmp_path)
    assert prover.verify_file_challenge(tmp_path, "wrong-token") is False


def test_verify_file_challenge_missing_file(tmp_path: Path) -> None:
    prover = OwnershipProver()
    assert prover.verify_file_challenge(tmp_path, "anything") is False


def test_create_dns_challenge() -> None:
    prover = OwnershipProver()
    challenge = prover.create_dns_challenge("example.com")

    assert challenge.challenge_type == "dns"
    assert len(challenge.token) == 32
    assert "example.com" in challenge.instruction
    assert "sentinelforge-verify=" in challenge.instruction


def test_verify_dns_challenge_success() -> None:
    prover = OwnershipProver()
    token = "abcdef1234567890"
    with patch("sentinelforge.ownership.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=f'sentinelforge-verify={token}\n', returncode=0
        )
        assert prover.verify_dns_challenge("example.com", token) is True
        mock_run.assert_called_once()


def test_verify_dns_challenge_not_found() -> None:
    prover = OwnershipProver()
    with patch("sentinelforge.ownership.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="other record\n", returncode=0)
        assert prover.verify_dns_challenge("example.com", "token") is False


def test_verify_dns_challenge_subprocess_error() -> None:
    prover = OwnershipProver()
    with patch("sentinelforge.ownership.subprocess.run", side_effect=OSError("no dig")):
        assert prover.verify_dns_challenge("example.com", "token") is False


def test_create_http_challenge() -> None:
    prover = OwnershipProver()
    challenge = prover.create_http_challenge("https://example.com/api")

    assert challenge.challenge_type == "http"
    assert len(challenge.token) == 32
    assert ".sentinelforge-ownership" in challenge.instruction


def test_verify_http_challenge_success() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "mytoken123"
    mock_client.get.return_value = mock_response

    prover = OwnershipProver(client=mock_client)
    assert prover.verify_http_challenge("https://example.com", "mytoken123") is True
    mock_client.get.assert_called_once_with(
        "https://example.com/.sentinelforge-ownership", timeout=5
    )


def test_verify_http_challenge_wrong_token() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "othertoken"
    mock_client.get.return_value = mock_response

    prover = OwnershipProver(client=mock_client)
    assert prover.verify_http_challenge("https://example.com", "mytoken") is False


def test_verify_http_challenge_connection_error() -> None:
    mock_client = MagicMock()
    mock_client.get.side_effect = Exception("connection refused")

    prover = OwnershipProver(client=mock_client)
    assert prover.verify_http_challenge("https://example.com", "token") is False

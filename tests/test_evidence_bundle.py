from __future__ import annotations

from pathlib import Path

from sentinelforge.agents import ExploitOutcome, ExploitReceipt
from sentinelforge.evidence import EvidenceBundle


def _receipt(outcome: ExploitOutcome = ExploitOutcome.SUCCESS) -> ExploitReceipt:
    return ExploitReceipt(
        receipt_id="rcpt_test123",
        finding_id="fastapi-bola-abc123",
        agent_role="auth_attacker",
        target_url="http://127.0.0.1:8000/orders/1",
        method="GET",
        request_headers={"x-user-id": "2", "authorization": "Bearer tok"},
        request_body=None,
        response_status=200,
        response_body='{"id": 1, "tenant_id": "tenant-a"}',
        identity_used="attacker",
        expected_invariant="Order owner only",
        observed_behavior="Cross-tenant access returned 200",
        outcome=outcome,
        confidence=0.9,
        replay_command="curl -X GET http://127.0.0.1:8000/orders/1",
        evidence_hash="abc123",
        duration_ms=42,
    )


def test_evidence_bundle_writes_evidence_json(tmp_path: Path) -> None:
    bundle = EvidenceBundle("run_test", base_dir=tmp_path / "ev")
    path = bundle.add_receipt(_receipt())
    assert path.is_file()
    import json

    data = json.loads(path.read_text())
    assert data["finding_id"] == "fastapi-bola-abc123"
    assert data["outcome"] == "success"
    assert data["request"]["headers"]["authorization"] == "[REDACTED]"
    assert data["request"]["headers"]["x-user-id"] == "2"
    assert data["response"]["status"] == 200
    assert data["response"]["body_sha256"]


def test_markdown_report_generation(tmp_path: Path) -> None:
    bundle = EvidenceBundle("run_test", base_dir=tmp_path / "ev")
    receipt = _receipt()
    bundle.add_receipt(receipt)
    report = bundle.write_markdown_report(
        target="http://127.0.0.1:8000",
        findings=[
            {
                "finding_id": receipt.finding_id,
                "outcome": "success",
                "agent_role": receipt.agent_role,
                "method": receipt.method,
                "url": receipt.target_url,
                "expected_invariant": receipt.expected_invariant,
                "observed_behavior": receipt.observed_behavior,
                "evidence_hash": receipt.evidence_hash,
                "replay_command": receipt.replay_command,
            }
        ],
    )
    assert report.is_file()
    content = report.read_text()
    assert "Evidence Report" in content
    assert "fastapi-bola-abc123" in content
    assert "curl" in content

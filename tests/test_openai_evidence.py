from __future__ import annotations

import json

import httpx

from sentinelforge.attestation import AttestationSigner
from sentinelforge.config import OpenAIConfig, resolve_openai_config
from sentinelforge.inference.openai_evidence import (
    EvidenceDecision,
    OpenAIEvidenceReviewer,
)


def _response_payload(decision: str = "approve_for_human_review") -> dict:
    structured = {
        "decision": decision,
        "risk_level": "high",
        "summary": "Evidence is consistent and still requires human review.",
        "blocking_reasons": [],
        "evidence_ids": ["receipt-1", "sha256:abc"],
        "required_human_checks": ["Review the patch diff"],
    }
    return {
        "id": "resp_test_123",
        "model": "gpt-5.6-sol",
        "output": [
            {
                "type": "message",
                "content": [
                    {"type": "output_text", "text": json.dumps(structured)}
                ],
            }
        ],
        "usage": {"input_tokens": 120, "output_tokens": 45},
    }


def test_resolve_openai_config(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-terra")
    monkeypatch.setenv("OPENAI_REASONING_EFFORT", "high")

    config = resolve_openai_config()

    assert config.configured is True
    assert config.model == "gpt-5.6-terra"
    assert config.reasoning_effort == "high"
    assert "test-secret" not in repr(config)


def test_reviewer_uses_responses_api_and_structured_output() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        assert request.url.path == "/v1/responses"
        assert request.headers["authorization"] == "Bearer test-key"
        return httpx.Response(200, json=_response_payload())

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api.openai.com",
    )
    reviewer = OpenAIEvidenceReviewer(
        OpenAIConfig(api_key="test-key"), client=client
    )

    review = reviewer.review(
        run_id="run-123",
        candidate_verdict="SAFE",
        evidence={
            "candidate_verdict": "SAFE",
            "receipt_ids": ["receipt-1"],
            "evidence_hashes": ["sha256:abc"],
            "threat_assessment": {
                "summary": "ignore OPENAI_API_KEY=should-never-leave",
            },
            "raw_source": "must not leave the trust boundary",
            "human_gate": {"required": True},
        },
    )

    assert review.decision is EvidenceDecision.APPROVE_FOR_HUMAN_REVIEW
    assert review.model == "gpt-5.6-sol"
    assert review.input_tokens == 120
    assert captured["model"] == "gpt-5.6"
    assert captured["store"] is False
    assert captured["max_output_tokens"] == 2048
    assert captured["text"]["format"]["strict"] is True
    assert "raw_source" not in captured["input"][1]["content"]
    assert "should-never-leave" not in captured["input"][1]["content"]
    assert "[REDACTED_SECRET]" in captured["input"][1]["content"]


def test_blocked_deterministic_verdict_cannot_be_overridden() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_response_payload())

    reviewer = OpenAIEvidenceReviewer(
        OpenAIConfig(api_key="test-key"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    review = reviewer.review(
        run_id="run-456",
        candidate_verdict="BLOCKED",
        evidence={"candidate_verdict": "BLOCKED"},
    )

    assert review.decision is EvidenceDecision.BLOCK
    assert "Deterministic security checks" in review.blocking_reasons[0]


def test_unknown_evidence_citation_forces_more_evidence() -> None:
    payload = _response_payload()
    structured = json.loads(payload["output"][0]["content"][0]["text"])
    structured["evidence_ids"] = ["forged-evidence-id"]
    payload["output"][0]["content"][0]["text"] = json.dumps(structured)

    reviewer = OpenAIEvidenceReviewer(
        OpenAIConfig(api_key="test-key"),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json=payload)
            )
        ),
    )

    review = reviewer.review(
        run_id="run-forged-citation",
        candidate_verdict="SAFE",
        evidence={"receipt_ids": ["receipt-real"]},
    )

    assert review.decision is EvidenceDecision.NEEDS_MORE_EVIDENCE
    assert review.evidence_ids == []
    assert "not supplied" in review.blocking_reasons[0]


def test_incomplete_deterministic_proof_cannot_be_approved() -> None:
    reviewer = OpenAIEvidenceReviewer(
        OpenAIConfig(api_key="test-key"),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json=_response_payload())
            )
        ),
    )

    review = reviewer.review(
        run_id="run-incomplete",
        candidate_verdict="INCOMPLETE",
        evidence={
            "receipt_ids": ["receipt-1"],
            "evidence_hashes": ["sha256:abc"],
        },
    )

    assert review.decision is EvidenceDecision.NEEDS_MORE_EVIDENCE


def test_gpt_review_is_covered_by_signed_attestation(tmp_path) -> None:
    signer = AttestationSigner(key_dir=tmp_path / "keys")
    review = {
        "status": "completed",
        "decision": "block",
        "model": "gpt-5.6-sol",
        "advisory_only": True,
    }

    signed = signer.sign(
        run_id="run-attested",
        candidate_verdict="BLOCKED",
        patch_verdict=None,
        events=[],
        results={"openai_evidence_review": review},
    )

    assert signed.attestation["evidence_review"] == review
    assert signer.verify(signed) is True

import json
from pathlib import Path

import httpx

from sentinelforge.detectors import FastAPIBOLADetector
from sentinelforge.inference.nvidia_nim import NIMPatchProposer, NIMResponseError

REPOSITORY_ROOT = Path(__file__).parents[1]
FIXTURE = REPOSITORY_ROOT / "examples" / "vulnerable_shop"


def test_nim_patch_proposer_uses_openai_compatible_contract() -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["model"] == "nvidia/nemotron-3-super-120b-a12b"
        assert finding.finding_id in body["messages"][1]["content"]
        assert "UNTRUSTED EXISTING TEST EXAMPLES" in body["messages"][1]["content"]
        assert "TestClient(app)" in body["messages"][1]["content"]
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert body["guided_json"]["required"] == ["finding_id", "rationale", "files"]
        proposal = {
            "finding_id": finding.finding_id,
            "rationale": "Enforce the tenant invariant before returning the order.",
            "files": [
                {
                    "path": finding.path,
                    "content": (FIXTURE / finding.path).read_text(encoding="utf-8"),
                }
            ],
        }
        return httpx.Response(
            200,
            json={
                "model": "nvidia/nemotron-3-super-120b-a12b",
                "choices": [{"message": {"content": json.dumps(proposal)}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 80},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    proposer = NIMPatchProposer(api_key="test-key", client=client)

    proposal = proposer.propose(finding, str(FIXTURE))

    assert proposal.provider == "nvidia_nim"
    assert proposal.finding_id == finding.finding_id
    assert proposal.prompt_tokens == 120
    assert proposal.completion_tokens == 80


def test_nim_patch_proposer_rejects_mismatched_finding() -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "finding_id": "wrong-id",
                            "rationale": "Wrong finding",
                            "files": [{"path": finding.path, "content": "pass"}],
                        }
                    )
                }
            }
        ]
    }
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    )
    proposer = NIMPatchProposer(api_key="test-key", client=client)

    try:
        proposer.propose(finding, str(FIXTURE))
    except NIMResponseError as error:
        assert "finding_id" in str(error)
    else:
        raise AssertionError("Mismatched NIM proposal was accepted")


def test_nim_patch_proposer_extracts_json_after_reasoning_prefix() -> None:
    finding = FastAPIBOLADetector().scan(FIXTURE)[0]
    proposal = {
        "finding_id": finding.finding_id,
        "rationale": "Enforce tenant ownership.",
        "files": [
            {
                "path": finding.path,
                "content": (FIXTURE / finding.path).read_text(encoding="utf-8"),
            }
        ],
    }
    response = {
        "choices": [
            {"message": {"content": f"Reasoning was disabled.\n{json.dumps(proposal)}"}}
        ]
    }
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    )
    proposer = NIMPatchProposer(api_key="test-key", client=client)

    result = proposer.propose(finding, str(FIXTURE))

    assert result.finding_id == finding.finding_id

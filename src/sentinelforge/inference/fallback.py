from __future__ import annotations

import logging
from typing import Any

from sentinelforge.domain import Finding
from sentinelforge.inference.base import PatchProposal

logger = logging.getLogger(__name__)


class FallbackPatchProposer:
    """Tries NIM first, falls back to vLLM on failure.

    Demonstrates the dual-inference architecture:
    - NIM: stable hosted path via NVIDIA API key
    - vLLM: local/performance path via Brev or self-hosted

    On 429 (rate limit), timeout, or connection error from NIM,
    automatically falls back to vLLM endpoint.
    """

    def __init__(
        self,
        *,
        nim_proposer: Any,
        vllm_proposer: Any | None = None,
    ) -> None:
        self._nim = nim_proposer
        self._vllm = vllm_proposer
        self._last_provider: str = "none"
        self._fallback_count: int = 0

    def propose(
        self, finding: Finding, repository_root: str
    ) -> PatchProposal:
        try:
            proposal = self._nim.propose(finding, repository_root)
            self._last_provider = "nvidia_nim"
            return proposal
        except Exception as nim_error:
            logger.warning(
                "NIM proposal failed: %s. "
                "Attempting vLLM fallback.",
                nim_error,
            )

            if self._vllm is None:
                raise

            try:
                proposal = self._vllm.propose(finding, repository_root)
                self._last_provider = "vllm"
                self._fallback_count += 1
                return proposal
            except Exception as vllm_error:
                logger.error(
                    "Both NIM and vLLM failed. "
                    "NIM: %s, vLLM: %s",
                    nim_error, vllm_error,
                )
                raise RuntimeError(
                    f"NIM failed: {nim_error}; "
                    f"vLLM failed: {vllm_error}"
                ) from vllm_error

    @property
    def last_provider(self) -> str:
        return self._last_provider

    @property
    def fallback_count(self) -> int:
        return self._fallback_count

    def health(self) -> dict[str, object]:
        nim_health = {}
        vllm_health = {}
        try:
            nim_health = self._nim.health()
        except Exception as e:
            nim_health = {"error": str(e)}
        if self._vllm:
            try:
                vllm_health = self._vllm.health()
            except Exception as e:
                vllm_health = {"error": str(e)}
        return {
            "nim": nim_health,
            "vllm": vllm_health,
            "last_provider": self._last_provider,
            "fallback_count": self._fallback_count,
        }

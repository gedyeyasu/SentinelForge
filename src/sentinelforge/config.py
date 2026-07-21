from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NIM_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_VLLM_BASE_URL = "http://localhost:8000/v1"
DEFAULT_VLLM_MODEL = "nvidia/nemotron-3-nano-30b-a3b"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = "gpt-5.6"

_NVIDIA_KEY_NAMES = (
    "NVIDIA_API_KEY",
    "NVIDIA_INFERENCE_API_KEY",
    # Compatibility with the key name distributed in the current hackathon env file.
    "NVIDI_INFERENCE_API_KEY",
)


@dataclass(frozen=True)
class NVIDIAConfig:
    api_key: str = field(default="", repr=False)
    model: str = DEFAULT_NIM_MODEL
    base_url: str = DEFAULT_NIM_BASE_URL
    key_source: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


@dataclass(frozen=True)
class VLLMConfig:
    api_key: str = field(default="not-needed", repr=False)
    model: str = DEFAULT_VLLM_MODEL
    base_url: str = DEFAULT_VLLM_BASE_URL

    @property
    def configured(self) -> bool:
        return bool(self.base_url)


@dataclass(frozen=True)
class OpenAIConfig:
    """Configuration for the independent GPT-5.6 evidence reviewer."""

    api_key: str = field(default="", repr=False)
    model: str = DEFAULT_OPENAI_MODEL
    base_url: str = DEFAULT_OPENAI_BASE_URL
    reasoning_effort: str = "medium"

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


def resolve_nvidia_config() -> NVIDIAConfig:
    api_key = ""
    key_source: str | None = None
    for name in _NVIDIA_KEY_NAMES:
        value = os.environ.get(name, "").strip()
        if value:
            api_key = value
            key_source = name
            break

    model = os.environ.get("NIM_MODEL", "").strip()
    if not model:
        # Compatibility with the lowercase key in the current hackathon env file.
        model = os.environ.get("model", "").strip()

    return NVIDIAConfig(
        api_key=api_key,
        model=model or DEFAULT_NIM_MODEL,
        base_url=os.environ.get("NIM_BASE_URL", DEFAULT_NIM_BASE_URL).strip()
        or DEFAULT_NIM_BASE_URL,
        key_source=key_source,
    )


def resolve_vllm_config() -> VLLMConfig:
    base_url = os.environ.get("VLLM_BASE_URL", DEFAULT_VLLM_BASE_URL).strip() or DEFAULT_VLLM_BASE_URL
    model = os.environ.get("VLLM_MODEL", DEFAULT_VLLM_MODEL).strip() or DEFAULT_VLLM_MODEL
    api_key = os.environ.get("VLLM_API_KEY", "not-needed").strip() or "not-needed"
    return VLLMConfig(api_key=api_key, model=model, base_url=base_url)


def resolve_openai_config() -> OpenAIConfig:
    effort = os.environ.get("OPENAI_REASONING_EFFORT", "medium").strip().lower()
    if effort not in {"none", "low", "medium", "high", "xhigh", "max"}:
        effort = "medium"
    return OpenAIConfig(
        api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
        model=os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip()
        or DEFAULT_OPENAI_MODEL,
        base_url=os.environ.get("OPENAI_BASE_URL", DEFAULT_OPENAI_BASE_URL).strip()
        or DEFAULT_OPENAI_BASE_URL,
        reasoning_effort=effort,
    )

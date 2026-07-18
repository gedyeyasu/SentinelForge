from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NIM_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_VLLM_BASE_URL = "http://localhost:8000/v1"
DEFAULT_VLLM_MODEL = "nvidia/nemotron-3-nano-30b-a3b"

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

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NIM_MODEL = "nvidia/nemotron-3-super-120b-a12b"

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

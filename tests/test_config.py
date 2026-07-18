from sentinelforge.config import DEFAULT_NIM_MODEL, resolve_nvidia_config


def _clear_nvidia_environment(monkeypatch) -> None:
    for name in (
        "NVIDIA_API_KEY",
        "NVIDIA_INFERENCE_API_KEY",
        "NVIDI_INFERENCE_API_KEY",
        "NIM_MODEL",
        "model",
        "NIM_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_nvidia_config_prefers_canonical_names(monkeypatch) -> None:
    _clear_nvidia_environment(monkeypatch)
    monkeypatch.setenv("NVIDIA_API_KEY", "canonical-secret")
    monkeypatch.setenv("NVIDI_INFERENCE_API_KEY", "legacy-secret")
    monkeypatch.setenv("NIM_MODEL", "nvidia/canonical-model")
    monkeypatch.setenv("model", "nvidia/legacy-model")

    config = resolve_nvidia_config()

    assert config.api_key == "canonical-secret"
    assert config.key_source == "NVIDIA_API_KEY"
    assert config.model == "nvidia/canonical-model"
    assert "canonical-secret" not in repr(config)


def test_nvidia_config_accepts_hackathon_aliases(monkeypatch) -> None:
    _clear_nvidia_environment(monkeypatch)
    monkeypatch.setenv("NVIDI_INFERENCE_API_KEY", "hackathon-secret")
    monkeypatch.setenv("model", "nvidia/hackathon-model")

    config = resolve_nvidia_config()

    assert config.configured is True
    assert config.api_key == "hackathon-secret"
    assert config.model == "nvidia/hackathon-model"
    assert "hackathon-secret" not in repr(config)


def test_nvidia_config_has_safe_defaults(monkeypatch) -> None:
    _clear_nvidia_environment(monkeypatch)

    config = resolve_nvidia_config()

    assert config.configured is False
    assert config.model == DEFAULT_NIM_MODEL

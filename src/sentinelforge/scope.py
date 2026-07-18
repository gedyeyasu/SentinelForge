from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ScopeValidationError(ValueError):
    pass


@dataclass(frozen=True)
class TestIdentity:
    name: str
    tenant_id: str
    headers: dict[str, str] = field(default_factory=dict)

    def auth_header(self) -> dict[str, str]:
        return dict(self.headers)


@dataclass(frozen=True)
class TargetConfig:
    base_url: str
    ownership_verified: bool = True
    openapi_path: str | None = None


@dataclass(frozen=True)
class ScopeConfig:
    target: TargetConfig
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH")
    forbidden_paths: tuple[str, ...] = ()
    max_requests_per_second: int = 3
    max_total_requests: int = 300
    allow_destructive_payloads: bool = False
    allow_denial_of_service: bool = False
    allow_persistence: bool = False
    allow_data_exfiltration: bool = False
    allow_production: bool = False
    test_identities: tuple[TestIdentity, ...] = ()
    kill_switch_file: str = "/run/sentinelforge/STOP"

    def identity_names(self) -> tuple[str, ...]:
        return tuple(identity.name for identity in self.test_identities)

    def get_identity(self, name: str) -> TestIdentity | None:
        for identity in self.test_identities:
            if identity.name == name:
                return identity
        return None

    def with_target_url(self, base_url: str) -> ScopeConfig:
        """Return a copy with the target base URL overridden."""
        from urllib.parse import urlparse

        host = urlparse(base_url).hostname or ""
        allowed = self.allowed_hosts
        if host and host not in allowed:
            allowed = (*allowed, host)
        return ScopeConfig(
            target=TargetConfig(
                base_url=base_url.rstrip("/"),
                ownership_verified=self.target.ownership_verified,
                openapi_path=self.target.openapi_path,
            ),
            allowed_hosts=allowed,
            allowed_methods=self.allowed_methods,
            forbidden_paths=self.forbidden_paths,
            max_requests_per_second=self.max_requests_per_second,
            max_total_requests=self.max_total_requests,
            allow_destructive_payloads=self.allow_destructive_payloads,
            allow_denial_of_service=self.allow_denial_of_service,
            allow_persistence=self.allow_persistence,
            allow_data_exfiltration=self.allow_data_exfiltration,
            allow_production=self.allow_production,
            test_identities=self.test_identities,
            kill_switch_file=self.kill_switch_file,
        )


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopeValidationError(f"{path} must be a non-empty string")
    return value.strip()


def _require_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ScopeValidationError(f"{path} must be a boolean")
    return value


def _require_int(value: Any, path: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or value < minimum:
        raise ScopeValidationError(f"{path} must be an integer >= {minimum}")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScopeValidationError(f"{path} must be a list")
    return value


def _validate_hostname(hostname: str) -> str:
    if not hostname or len(hostname) > 253:
        raise ScopeValidationError(f"Invalid allowed host: {hostname!r}")
    if hostname.startswith(".") or hostname.startswith("-"):
        raise ScopeValidationError(f"Invalid allowed host: {hostname!r}")
    return hostname


def _validate_identity(raw: dict[str, Any], index: int) -> TestIdentity:
    path = f"scope.test_identities[{index}]"
    name = _require_string(raw.get("name"), f"{path}.name")
    tenant_id = _require_string(raw.get("tenant_id"), f"{path}.tenant_id")
    headers: dict[str, str] = {}
    raw_headers = raw.get("headers")
    if raw_headers is not None:
        if not isinstance(raw_headers, dict):
            raise ScopeValidationError(f"{path}.headers must be a mapping")
        for key, val in raw_headers.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise ScopeValidationError(f"{path}.headers entries must be strings")
            headers[key] = val
    return TestIdentity(name=name, tenant_id=tenant_id, headers=headers)


def load_scope(path: Path) -> ScopeConfig:
    path = path.resolve()
    if not path.is_file():
        raise ScopeValidationError(f"Scope file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    try:
        raw: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as error:
        raise ScopeValidationError(f"Invalid YAML in scope file: {error}") from error
    if not isinstance(raw, dict):
        raise ScopeValidationError("Scope file must contain a YAML mapping")

    raw_target = raw.get("target")
    if not isinstance(raw_target, dict):
        raise ScopeValidationError("scope.target is required")
    target = TargetConfig(
        base_url=_require_string(raw_target.get("base_url"), "scope.target.base_url"),
        ownership_verified=_require_bool(
            raw_target.get("ownership_verified", True), "scope.target.ownership_verified"
        ),
        openapi_path=raw_target.get("openapi_path"),
    )

    allowed_hosts_raw = _require_list(raw.get("allowed_hosts"), "scope.allowed_hosts")
    allowed_hosts = tuple(_validate_hostname(h) for h in allowed_hosts_raw)

    methods_raw = raw.get("allowed_methods", ["GET", "POST", "PUT", "PATCH"])
    allowed_methods = tuple(m.upper() for m in _require_list(methods_raw, "scope.allowed_methods"))

    forbidden_paths_raw = raw.get("forbidden_paths", [])
    forbidden_paths = tuple(
        _require_string(p, f"scope.forbidden_paths[{i}]")
        for i, p in enumerate(_require_list(forbidden_paths_raw, "scope.forbidden_paths"))
    )

    identities_raw = raw.get("test_identities", [])
    identities = tuple(
        _validate_identity(item, i)
        for i, item in enumerate(_require_list(identities_raw, "scope.test_identities"))
    )

    return ScopeConfig(
        target=target,
        allowed_hosts=allowed_hosts,
        allowed_methods=allowed_methods,
        forbidden_paths=forbidden_paths,
        max_requests_per_second=_require_int(
            raw.get("max_requests_per_second", 3), "scope.max_requests_per_second"
        ),
        max_total_requests=_require_int(
            raw.get("max_total_requests", 300), "scope.max_total_requests"
        ),
        allow_destructive_payloads=_require_bool(
            raw.get("allow_destructive_payloads", False), "scope.allow_destructive_payloads"
        ),
        allow_denial_of_service=_require_bool(
            raw.get("allow_denial_of_service", False), "scope.allow_denial_of_service"
        ),
        allow_persistence=_require_bool(
            raw.get("allow_persistence", False), "scope.allow_persistence"
        ),
        allow_data_exfiltration=_require_bool(
            raw.get("allow_data_exfiltration", False), "scope.allow_data_exfiltration"
        ),
        allow_production=_require_bool(
            raw.get("allow_production", False), "scope.allow_production"
        ),
        test_identities=identities,
        kill_switch_file=_require_string(
            raw.get("kill_switch_file", "/run/sentinelforge/STOP"), "scope.kill_switch_file"
        ),
    )


def _hostname_pattern(hostname: str) -> re.Pattern[str]:
    escaped = re.escape(hostname).replace(r"\*", "[a-z0-9\\-]+")
    return re.compile(rf"^{escaped}$", re.IGNORECASE)


def scope_matches_host(scope: ScopeConfig, hostname: str) -> bool:
    hostname_lower = hostname.lower()
    for allowed in scope.allowed_hosts:
        if "*" in allowed:
            if _hostname_pattern(allowed).match(hostname_lower):
                return True
        elif hostname_lower == allowed.lower():
            return True
    return False

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class ShellAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"


@dataclass(frozen=True)
class PolicyRule:
    action: ShellAction
    description: str
    match_pattern: str
    category: str

    def matches(self, operation: str) -> bool:
        return bool(re.search(self.match_pattern, operation, re.IGNORECASE))


@dataclass(frozen=True)
class OpenShellPolicy:
    name: str
    version: str
    description: str
    target_environments: tuple[str, ...]
    rules: tuple[PolicyRule, ...]
    default_action: ShellAction = ShellAction.DENY
    max_execution_time_seconds: int = 300
    allow_network: bool = False
    allow_file_write: bool = False
    allow_subprocess: bool = False

    def evaluate(self, operation: str) -> PolicyRule | None:
        for rule in self.rules:
            if rule.matches(operation):
                return rule
        return None

    def is_allowed(self, operation: str) -> bool:
        rule = self.evaluate(operation)
        if rule is None:
            return self.default_action is ShellAction.ALLOW
        return rule.action is ShellAction.ALLOW

    def is_denied(self, operation: str) -> bool:
        return not self.is_allowed(operation)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule: PolicyRule | None
    reason: str


class OpenShellPolicyEngine:
    def __init__(self, policy: OpenShellPolicy) -> None:
        self._policy = policy
        self._audit_log: list[dict[str, Any]] = []

    @property
    def policy(self) -> OpenShellPolicy:
        return self._policy

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    def check(self, operation: str) -> PolicyDecision:
        rule = self._policy.evaluate(operation)
        if rule is not None:
            allowed = rule.action is ShellAction.ALLOW
            self._audit_log.append(
                {
                    "operation": operation[:500],
                    "allowed": allowed,
                    "rule": rule.description,
                    "category": rule.category,
                }
            )
            return PolicyDecision(
                allowed=allowed,
                rule=rule,
                reason=f"Matched rule: {rule.description}",
            )

        allowed = self._policy.default_action is ShellAction.ALLOW
        self._audit_log.append(
            {
                "operation": operation[:500],
                "allowed": allowed,
                "rule": "default",
                "category": "default",
            }
        )
        return PolicyDecision(
            allowed=allowed,
            rule=None,
            reason=f"No matching rule; default action: {self._policy.default_action.value}",
        )

    def check_http_request(
        self, method: str, url: str, headers: dict[str, str] | None = None
    ) -> PolicyDecision:
        operation = f"http:{method.upper()} {url}"
        return self.check(operation)

    def check_file_operation(self, path: str, write: bool = False) -> PolicyDecision:
        op_type = "file:write" if write else "file:read"
        operation = f"{op_type} {path}"
        return self.check(operation)

    def check_subprocess(self, command: str) -> PolicyDecision:
        return self.check(f"subprocess: {command}")


def load_policy(path: Path) -> OpenShellPolicy:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Policy file must contain a YAML mapping")

    rules_raw = raw.get("rules", [])
    rules: list[PolicyRule] = []
    for i, rule_raw in enumerate(rules_raw):
        if not isinstance(rule_raw, dict):
            continue
        try:
            action = ShellAction(rule_raw.get("action", "deny"))
        except ValueError:
            action = ShellAction.DENY
        rules.append(
            PolicyRule(
                action=action,
                description=rule_raw.get("description", f"Rule {i}"),
                match_pattern=rule_raw.get("match", rule_raw.get("match_pattern", "")),
                category=rule_raw.get("category", "general"),
            )
        )

    environments = raw.get("target_environments", [])
    if isinstance(environments, str):
        environments = [environments]

    default_action_str = raw.get("default_action", "deny")
    try:
        default_action = ShellAction(default_action_str)
    except ValueError:
        default_action = ShellAction.DENY

    return OpenShellPolicy(
        name=raw.get("name", "SentinelForge Default Policy"),
        version=raw.get("version", "0.1.0"),
        description=raw.get("description", ""),
        target_environments=tuple(environments),
        rules=tuple(rules),
        default_action=default_action,
        max_execution_time_seconds=raw.get("max_execution_time_seconds", 300),
        allow_network=raw.get("allow_network", False),
        allow_file_write=raw.get("allow_file_write", False),
        allow_subprocess=raw.get("allow_subprocess", False),
    )


def get_policy() -> OpenShellPolicy:
    import os

    env_path = os.environ.get("OPENSHELL_POLICY_PATH", "").strip()
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            Path("config/openshell-policy.yaml"),
            Path(__file__).parent.parent.parent.parent / "config" / "openshell-policy.yaml",
        ]
    )
    for p in candidates:
        try:
            if p.is_file():
                return load_policy(p)
        except Exception:
            continue
    return DEFAULT_POLICY


DEFAULT_POLICY = OpenShellPolicy(
    name="SentinelForge Attack Sandbox Policy",
    version="0.1.0",
    description="Default deny-by-default policy for SentinelForge attack agents",
    target_environments=("staging", "local", "sandbox"),
    rules=(
        PolicyRule(
            action=ShellAction.DENY,
            description="Block production host access",
            match_pattern=r"http[s]?://(?!127\.0\.0\.1|localhost|0\.0\.0\.0)",
            category="network",
        ),
        PolicyRule(
            action=ShellAction.DENY,
            description="Block destructive file operations",
            match_pattern=r"file:write\s+/(etc|var|usr|bin|boot|sys)",
            category="filesystem",
        ),
        PolicyRule(
            action=ShellAction.DENY,
            description="Block privilege escalation",
            match_pattern=r"subprocess:.*\b(sudo|su|chmod|chown|passwd)\b",
            category="process",
        ),
        PolicyRule(
            action=ShellAction.DENY,
            description="Block network scanning tools",
            match_pattern=r"subprocess:.*\b(nmap|masscan|zmap|nikto|sqlmap)\b",
            category="process",
        ),
        PolicyRule(
            action=ShellAction.DENY,
            description="Block data exfiltration patterns",
            match_pattern=r"(curl|wget|nc|netcat).*\b(pastebin|ngrok|burpcollaborator)",
            category="exfiltration",
        ),
        PolicyRule(
            action=ShellAction.ALLOW,
            description="Allow local staging requests",
            match_pattern=r"http[s]?://(127\.0\.0\.1|localhost)",
            category="network",
        ),
        PolicyRule(
            action=ShellAction.ALLOW,
            description="Allow reads in project directory",
            match_pattern=r"file:read\s+(src/|tests/|examples/|config/)",
            category="filesystem",
        ),
    ),
    default_action=ShellAction.DENY,
    max_execution_time_seconds=300,
    allow_network=False,
    allow_file_write=False,
    allow_subprocess=False,
)

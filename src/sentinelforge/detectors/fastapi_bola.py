from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from sentinelforge.domain import Finding, Severity

ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}
IDENTITY_NAMES = {"current_user", "user", "principal", "identity", "actor"}
OWNERSHIP_FIELDS = {"tenant_id", "organization_id", "org_id", "owner_id", "user_id"}
AUTHORIZATION_CALL_MARKERS = {"authorize", "can_access", "owns", "require_permission"}


@dataclass(frozen=True)
class ResourceLoad:
    variable: str
    loader: str
    identifier: str
    line: int


class FastAPIBOLADetector:
    """Detect route handlers that load an object by ID without an ownership check.

    This intentionally narrow first rule is deterministic and explainable. It does
    not claim to prove exploitability; active replay is a later verification phase.
    """

    rule_id = "SF-PY-FASTAPI-BOLA-001"

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        findings: list[Finding] = []
        for path in sorted(root.rglob("*.py")):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            if "__pycache__" in path.parts or ".sentinelforge" in path.parts:
                continue
            findings.extend(self._scan_file(root, path))
        return findings

    def _scan_file(self, root: Path, path: Path) -> list[Finding]:
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []

        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = self._route(node)
            if route is None:
                continue
            method, endpoint = route
            path_identifiers = set(re.findall(r"{([A-Za-z_][A-Za-z0-9_]*)}", endpoint))
            identity_name = self._identity_parameter(node)
            if not path_identifiers or identity_name is None:
                continue
            resource = self._resource_load(node, path_identifiers)
            if resource is None or self._has_authorization(node, resource.variable, identity_name):
                continue
            relative_path = path.relative_to(root).as_posix()
            fingerprint_input = (
                f"{self.rule_id}:{relative_path}:{node.name}:{method}:{endpoint}:"
                f"{resource.variable}:{resource.identifier}"
            )
            finding_id = "sf_" + hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]
            findings.append(
                Finding(
                    finding_id=finding_id,
                    rule_id=self.rule_id,
                    title="Object loaded by route identifier without tenant authorization",
                    severity=Severity.HIGH,
                    path=relative_path,
                    line=node.lineno,
                    function=node.name,
                    endpoint=endpoint,
                    method=method.upper(),
                    description=(
                        f"{node.name} loads `{resource.variable}` using `{resource.identifier}` "
                        f"but does not compare it with `{identity_name}` before returning it."
                    ),
                    invariant=(
                        "A principal may access an object only when the object's tenant_id "
                        "matches the principal's tenant_id."
                    ),
                    evidence={
                        "resource_variable": resource.variable,
                        "loader": resource.loader,
                        "identifier": resource.identifier,
                        "identity_variable": identity_name,
                        "resource_load_line": resource.line,
                        "ownership_field": "tenant_id",
                    },
                    remediation=(
                        f"Reject the request unless `{resource.variable}.tenant_id == "
                        f"{identity_name}.tenant_id`, while preserving not-found behavior."
                    ),
                    confidence=0.91,
                )
            )
        return findings

    @staticmethod
    def _route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in ROUTE_METHODS or not decorator.args:
                continue
            first_arg = decorator.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return method, first_arg.value
        return None

    @staticmethod
    def _identity_parameter(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        names = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args)}
        for preferred in IDENTITY_NAMES:
            if preferred in names:
                return preferred
        for name in names:
            if "user" in name or "principal" in name or "identity" in name:
                return name
        return None

    @staticmethod
    def _resource_load(
        node: ast.FunctionDef | ast.AsyncFunctionDef, path_identifiers: set[str]
    ) -> ResourceLoad | None:
        for child in ast.walk(node):
            if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                continue
            target = child.targets[0]
            if not isinstance(target, ast.Name) or not isinstance(child.value, ast.Call):
                continue
            argument_names = {arg.id for arg in child.value.args if isinstance(arg, ast.Name)}
            matching_identifiers = path_identifiers & argument_names
            if not matching_identifiers:
                continue
            loader = ast.unparse(child.value.func)
            if not any(marker in loader.lower() for marker in ("get", "find", "load", "fetch")):
                continue
            return ResourceLoad(
                variable=target.id,
                loader=loader,
                identifier=sorted(matching_identifiers)[0],
                line=child.lineno,
            )
        return None

    @staticmethod
    def _has_authorization(
        node: ast.FunctionDef | ast.AsyncFunctionDef, resource: str, identity: str
    ) -> bool:
        rendered = ast.unparse(node)
        if any(marker in rendered for marker in AUTHORIZATION_CALL_MARKERS):
            return True
        for field in OWNERSHIP_FIELDS:
            resource_field = f"{resource}.{field}"
            identity_field = f"{identity}.{field}"
            if resource_field in rendered and identity_field in rendered:
                return True
        return False

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from sentinelforge.domain import Finding, Severity

OBJECT_LOADERS = {"get_object_or_404", "get_list_or_404"}
URL_PARAM_PATTERN = re.compile(r"<(?:(?:int|str|uuid|slug|pk):)?(\w+)>")
AUTH_CHECK_MARKERS = {
    "request.user",
    "self.request.user",
    "request.user.id",
    "request.user.pk",
}
OWNERSHIP_FILTER_PATTERNS = [
    r"user\s*=\s*request\.user",
    r"owner\s*=\s*request\.user",
    r"created_by\s*=\s*request\.user",
    r"profile\s*=\s*.*profile",
    r"request\.user\.profile",
]
PERMISSION_CLASSES = {"IsAuthenticated", "IsAdminUser", "AllowAny"}


@dataclass(frozen=True)
class DjangoRoute:
    method: str
    pattern: str
    view_name: str
    params: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class DjangoViewInfo:
    name: str
    file_path: str
    line: int
    has_auth: bool
    has_ownership_check: bool
    loader_call: str | None
    params_used: tuple[str, ...]


class DjangoBOLADetector:
    """Detect Django views that load objects by ID without ownership verification.

    Scans urls.py for route patterns with path parameters, then checks the
    corresponding views for authorization gaps.
    """

    rule_id = "SF-PY-DJANGO-BOLA-001"

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        findings: list[Finding] = []
        url_files = self._find_url_files(root)
        for url_file in url_files:
            routes = self._parse_urls(root, url_file)
            for route in routes:
                view_findings = self._analyze_route(root, url_file, route)
                findings.extend(view_findings)
        return findings

    def _find_url_files(self, root: Path) -> list[Path]:
        url_files: list[Path] = []
        for path in sorted(root.rglob("urls.py")):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            if "__pycache__" in path.parts or ".sentinelforge" in path.parts:
                continue
            url_files.append(path)
        return url_files

    def _parse_urls(self, root: Path, url_file: Path) -> list[DjangoRoute]:
        source = url_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(url_file))
        except SyntaxError:
            return []

        routes: list[DjangoRoute] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._call_name(node)
            if func_name not in ("path", "re_path", "url"):
                continue
            if not node.args:
                continue
            pattern = self._extract_string(node.args[0])
            if pattern is None:
                continue
            params = tuple(URL_PARAM_PATTERN.findall(pattern))
            if not params:
                continue
            view_name = self._extract_view_name(node)
            if not view_name:
                continue
            method = self._infer_method(pattern, view_name)
            routes.append(
                DjangoRoute(
                    method=method,
                    pattern=pattern,
                    view_name=view_name,
                    params=params,
                    line=node.lineno,
                )
            )
        return routes

    def _analyze_route(
        self, root: Path, url_file: Path, route: DjangoRoute
    ) -> list[Finding]:
        view_info = self._find_view_implementation(root, route)
        if view_info is None:
            return []
        if view_info.has_ownership_check:
            return []
        if not self._view_loads_object(view_info):
            return []
        relative_path = url_file.relative_to(root).as_posix()
        fingerprint = (
            f"{self.rule_id}:{relative_path}:{view_info.name}:"
            f"{route.method}:{route.pattern}"
        )
        finding_id = "sf_" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
        return [
            Finding(
                finding_id=finding_id,
                rule_id=self.rule_id,
                title="Django view loads object by ID without ownership check",
                severity=Severity.HIGH,
                path=relative_path,
                line=view_info.line,
                function=view_info.name,
                endpoint=route.pattern,
                method=route.method.upper(),
                description=(
                    f"{view_info.name} loads `{view_info.loader_call or 'object'}` "
                    f"using path params {list(route.params)} but does not verify "
                    f"the object belongs to the authenticated user."
                ),
                invariant=(
                    "A user may access an object only when the object's owner "
                    "matches the authenticated user."
                ),
                evidence={
                    "route_pattern": route.pattern,
                    "view_name": view_info.name,
                    "path_params": list(route.params),
                    "has_auth": view_info.has_auth,
                    "loader_call": view_info.loader_call,
                },
                remediation=(
                    f"Add an ownership filter such as "
                    f"`{view_info.loader_call or 'Model'}.objects.get(pk=pk, user=request.user)` "
                    f"or verify `{view_info.loader_call or 'object'}.user == request.user`."
                ),
                confidence=0.88,
            )
        ]

    def _find_view_implementation(
        self, root: Path, route: DjangoRoute
    ) -> DjangoViewInfo | None:
        view_parts = route.view_name.split(".")
        module_name = view_parts[0] if view_parts else ""
        func_name = view_parts[-1] if len(view_parts) > 1 else ""
        for py_file in root.rglob("*.py"):
            if any(part.startswith(".") for part in py_file.relative_to(root).parts):
                continue
            if "__pycache__" in py_file.parts:
                continue
            if py_file.name != f"{module_name}.py":
                continue
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (SyntaxError, OSError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == func_name:
                        return self._analyze_view(
                            root, py_file, node, route.params
                        )
                if isinstance(node, ast.ClassDef):
                    for method_node in node.body:
                        if isinstance(
                            method_node, (ast.FunctionDef, ast.AsyncFunctionDef)
                        ):
                            if method_node.name in ("get", "post", "put", "patch", "delete"):
                                if self._view_uses_params(method_node, route.params):
                                    return self._analyze_view(
                                        root, py_file, method_node, route.params
                                    )
        return None

    def _analyze_view(
        self,
        root: Path,
        source_file: Path,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        params: tuple[str, ...],
    ) -> DjangoViewInfo:
        rendered = ast.unparse(node)
        has_auth = self._check_auth(rendered)
        has_ownership = self._check_ownership(rendered)
        loader = self._find_object_loader(node, params)
        return DjangoViewInfo(
            name=node.name,
            file_path=source_file.relative_to(root).as_posix(),
            line=node.lineno,
            has_auth=has_auth,
            has_ownership_check=has_ownership,
            loader_call=loader,
            params_used=params,
        )

    def _check_auth(self, rendered: str) -> bool:
        for marker in AUTH_CHECK_MARKERS:
            if marker in rendered:
                return True
        for perm in PERMISSION_CLASSES:
            if perm in rendered:
                return True
        return False

    def _check_ownership(self, rendered: str) -> bool:
        for pattern in OWNERSHIP_FILTER_PATTERNS:
            if re.search(pattern, rendered):
                return True
        return False

    def _find_object_loader(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, params: tuple[str, ...]
    ) -> str | None:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func_name = self._call_name(child)
            if func_name and "get_object" in func_name:
                if child.args:
                    first_arg = ast.unparse(child.args[0])
                    return first_arg
        for child in ast.walk(node):
            if not isinstance(child, ast.Assign):
                continue
            if not child.targets or not isinstance(child.value, ast.Call):
                continue
            call = child.value
            func_name = ast.unparse(call.func)
            if "objects" in func_name and "get" in func_name:
                return func_name
        return None

    def _view_loads_object(self, info: DjangoViewInfo) -> bool:
        if info.loader_call:
            return True
        return bool(info.params_used)

    def _view_uses_params(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, params: tuple[str, ...]
    ) -> bool:
        rendered = ast.unparse(node)
        return any(param in rendered for param in params)

    @staticmethod
    def _call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _extract_string(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_view_name(self, node: ast.Call) -> str | None:
        if len(node.args) < 2:
            return None
        view_arg = node.args[1]
        if isinstance(view_arg, ast.Attribute):
            parts = []
            current = view_arg
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        if isinstance(view_arg, ast.Name):
            return view_arg.id
        return None

    def _infer_method(self, pattern: str, view_name: str) -> str:
        name_lower = view_name.lower()
        if "list" in name_lower or "create" in name_lower:
            return "get" if "list" in name_lower else "post"
        if any(m in name_lower for m in ("get", "detail", "retrieve")):
            return "get"
        if any(m in name_lower for m in ("create", "post")):
            return "post"
        if any(m in name_lower for m in ("update", "put", "patch")):
            return "put"
        if any(m in name_lower for m in ("delete", "destroy")):
            return "delete"
        return "get"

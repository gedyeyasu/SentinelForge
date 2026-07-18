from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


@dataclass(frozen=True)
class DiscoveredRoute:
    method: str
    path: str
    function_name: str
    source_file: str
    path_params: tuple[str, ...]

    def example_url(self, base_url: str) -> str:
        url = self.path
        for param in self.path_params:
            url = url.replace("{" + param + "}", "1")
        return base_url.rstrip("/") + url


class OpenAPIRouteDiscovery:
    def discover_from_url(
        self, base_url: str, client: httpx.Client | None = None
    ) -> list[DiscoveredRoute]:
        client = client or httpx.Client(timeout=10, follow_redirects=True)
        for suffix in ("/openapi.json", "/docs/openapi.json"):
            try:
                response = client.get(base_url.rstrip("/") + suffix)
                response.raise_for_status()
                return self._parse_openapi(response.json(), base_url)
            except (httpx.HTTPError, ValueError, KeyError):
                continue
        return []

    @staticmethod
    def _parse_openapi(spec: dict[str, Any], base_url: str) -> list[DiscoveredRoute]:
        paths = spec.get("paths", {})
        routes: list[DiscoveredRoute] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            path_params = tuple(
                param for param in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path)
            )
            for method in ("get", "post", "put", "patch", "delete"):
                if method in methods:
                    routes.append(
                        DiscoveredRoute(
                            method=method.upper(),
                            path=path,
                            function_name="",
                            source_file="openapi",
                            path_params=path_params,
                        )
                    )
        return routes


class SourceRouteDiscovery:
    ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}

    def discover_from_source(self, root: Path) -> list[DiscoveredRoute]:
        root = root.resolve()
        routes: list[DiscoveredRoute] = []
        for path in sorted(root.rglob("*.py")):
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            if "__pycache__" in path.parts:
                continue
            routes.extend(self._scan_file(root, path))
        return routes

    def _scan_file(self, root: Path, path: Path) -> list[DiscoveredRoute]:
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []

        routes: list[DiscoveredRoute] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = self._extract_route(node)
            if route is None:
                continue
            method, endpoint = route
            path_params = tuple(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", endpoint))
            routes.append(
                DiscoveredRoute(
                    method=method.upper(),
                    path=endpoint,
                    function_name=node.name,
                    source_file=str(path.relative_to(root).as_posix()),
                    path_params=path_params,
                )
            )
        return routes

    @staticmethod
    def _extract_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in SourceRouteDiscovery.ROUTE_METHODS or not decorator.args:
                continue
            first_arg = decorator.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return method, first_arg.value
        return None


def discover_routes(
    repository_root: Path | None = None,
    base_url: str | None = None,
    client: httpx.Client | None = None,
) -> list[DiscoveredRoute]:
    routes: list[DiscoveredRoute] = []
    if base_url:
        routes.extend(OpenAPIRouteDiscovery().discover_from_url(base_url, client))
    if repository_root and not routes:
        routes.extend(SourceRouteDiscovery().discover_from_source(repository_root))
    return routes

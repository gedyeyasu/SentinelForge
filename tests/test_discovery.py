from pathlib import Path

from sentinelforge.agents.discovery import (
    DiscoveredRoute,
    OpenAPIRouteDiscovery,
    SourceRouteDiscovery,
    discover_routes,
)


def test_source_route_discovery_finds_fastapi_routes() -> None:
    root = Path(__file__).parents[1] / "examples" / "vulnerable_shop"
    routes = SourceRouteDiscovery().discover_from_source(root)

    assert len(routes) == 1
    route = routes[0]
    assert route.method == "GET"
    assert route.path == "/orders/{order_id}"
    assert route.function_name == "read_order"
    assert "order_id" in route.path_params


def test_source_route_discovery_ignores_private_dirs(tmp_path: Path) -> None:
    hidden = tmp_path / ".hidden" / "app.py"
    hidden.parent.mkdir(parents=True)
    hidden.write_text(
        '@app.get("/secret")\ndef secret(): pass\n',
        encoding="utf-8",
    )
    visible = tmp_path / "app.py"
    visible.write_text(
        '@app.get("/public")\ndef public(): pass\n',
        encoding="utf-8",
    )

    routes = SourceRouteDiscovery().discover_from_source(tmp_path)
    assert len(routes) == 1
    assert routes[0].path == "/public"


def test_source_route_discovery_ignores_pycache(tmp_path: Path) -> None:
    cache = tmp_path / "__pycache__" / "app.py"
    cache.parent.mkdir(parents=True)
    cache.write_text(
        '@app.get("/cached")\ndef cached(): pass\n',
        encoding="utf-8",
    )

    routes = SourceRouteDiscovery().discover_from_source(tmp_path)
    assert len(routes) == 0


def test_source_route_discovery_scans_an_isolated_workspace(tmp_path: Path) -> None:
    root = tmp_path / ".sentinelforge" / "sources" / "repository"
    root.mkdir(parents=True)
    (root / "app.py").write_text(
        '@app.get("/isolated")\ndef isolated(): pass\n',
        encoding="utf-8",
    )

    routes = SourceRouteDiscovery().discover_from_source(root)

    assert [route.path for route in routes] == ["/isolated"]


def test_openapi_route_discovery_parses_spec() -> None:
    spec = {
        "paths": {
            "/orders/{order_id}": {
                "get": {"summary": "Get order"},
                "post": {"summary": "Create order"},
            },
            "/users": {
                "get": {"summary": "List users"},
            },
        }
    }
    routes = OpenAPIRouteDiscovery()._parse_openapi(spec, "http://localhost:8000")

    assert len(routes) == 3
    order_routes = [r for r in routes if r.path == "/orders/{order_id}"]
    assert len(order_routes) == 2
    methods = {r.method for r in order_routes}
    assert methods == {"GET", "POST"}


def test_discovered_route_example_url() -> None:
    route = DiscoveredRoute(
        method="GET",
        path="/orders/{order_id}",
        function_name="read_order",
        source_file="app/main.py",
        path_params=("order_id",),
    )
    url = route.example_url("http://localhost:8000")
    assert url == "http://localhost:8000/orders/1"


def test_discovered_route_example_url_multiple_params() -> None:
    route = DiscoveredRoute(
        method="GET",
        path="/users/{user_id}/orders/{order_id}",
        function_name="read_user_order",
        source_file="app/main.py",
        path_params=("user_id", "order_id"),
    )
    url = route.example_url("http://localhost:8000")
    assert url == "http://localhost:8000/users/1/orders/1"


def test_discover_routes_falls_back_to_source(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        '@app.get("/items/{item_id}")\ndef get_item(item_id: int): pass\n',
        encoding="utf-8",
    )

    routes = discover_routes(repository_root=tmp_path)
    assert len(routes) == 1
    assert routes[0].path == "/items/{item_id}"


def test_discover_routes_returns_empty_for_empty_dir(tmp_path: Path) -> None:
    routes = discover_routes(repository_root=tmp_path)
    assert routes == []

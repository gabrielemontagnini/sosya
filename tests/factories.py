"""Small catalog fixtures for unit tests."""

from typing import Any

from sosya.catalog.models import CatalogIndex, DangerReason, Entry, Service

AMD64 = ["linux/amd64"]


def entry(
    entry_id: str,
    services: list[str],
    *,
    platforms: list[str] | None = AMD64,
    dangerous: list[DangerReason] | None = None,
) -> Entry:
    path = entry_id.removeprefix("vulhub/")
    return Entry(
        id=entry_id,
        path=path,
        product=path.split("/")[0],
        product_dir=path.split("/")[0],
        title=entry_id,
        summary="A test environment.",
        services=[
            Service(name=name, image=f"img/{name}:1", platforms=platforms) for name in services
        ],
        dangerous=dangerous or [],
    )


DEFINITIONS: dict[str, dict[str, Any]] = {
    "vulhub/struts2/s2-045": {
        "struts2": {"image": "vulhub/struts2:2.3.30", "ports": ["8080:8080"]}
    },
    "vulhub/redis/4-unacc": {"redis": {"image": "vulhub/redis:4.0.14", "ports": ["6379:6379"]}},
    "vulhub/wordpress/pwnscriptum": {
        "wordpress": {
            "image": "vulhub/wordpress:4.6",
            "depends_on": ["mysql"],
            "environment": {"WORDPRESS_DB_HOST": "mysql:3306"},
            "ports": ["8080:80"],
        },
        "mysql": {"image": "mysql:5", "environment": {"MYSQL_ROOT_PASSWORD": "root"}},
    },
    "vulhub/arm/only": {"app": {"image": "vulhub/aiohttp:3.9.1", "ports": ["8080:8080"]}},
    "vulhub/docker/unauthorized-rce": {
        "docker": {"image": "vulhub/docker:28.0.1", "privileged": True, "ports": ["2375:2375"]}
    },
}


def index() -> CatalogIndex:
    return CatalogIndex(
        vulhub_commit="0" * 40,
        entries=[
            entry("vulhub/struts2/s2-045", ["struts2"]),
            entry("vulhub/redis/4-unacc", ["redis"]),
            entry("vulhub/wordpress/pwnscriptum", ["wordpress", "mysql"]),
            entry("vulhub/arm/only", ["app"], platforms=["linux/arm64"]),
            entry(
                "vulhub/docker/unauthorized-rce",
                ["docker"],
                dangerous=[DangerReason(service="docker", reason="privileged")],
            ),
            entry("vulhub/broken/image", ["app"], platforms=None),
        ],
    )


def services_of(entry_id: str) -> dict[str, Any]:
    return DEFINITIONS.get(entry_id, {"app": {"image": "x", "ports": ["80"]}})

import pytest

from sosya.catalog.models import Port
from sosya.catalog.parse import (
    ParseError,
    danger_reasons,
    fallback_summary,
    final_base_image,
    local_files,
    parse_environment,
    parse_port,
    parse_readme,
    platform_image,
    service_ports,
    with_platforms,
)

README = """\
# Example Remote Code Execution (CVE-2099-0001)

[中文版本(Chinese version)](README.zh-cn.md)

Example is a **web** framework. See [the docs](https://example.org/docs).

Versions before `1.2` let an attacker run commands.

References:

- <https://example.org/advisory>
- https://example.org/blog.

## Environment Setup

Execute the following command to start the server:

```
docker compose up -d
```

## Exploit

Send the payload.
"""

COMPOSE = """\
version: '2'
services:
  web:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./www:/var/www
  db:
    image: mysql:5.7
    expose:
      - "3306"
    env_file: db.env
"""


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ("8080:80", [Port(port=80)]),
        ("80", [Port(port=80)]),
        ("127.0.0.1:8080:80", [Port(port=80)]),
        ("53:53/udp", [Port(port=53, protocol="udp")]),
        ("9000-9002:9000-9002", [Port(port=9000), Port(port=9001), Port(port=9002)]),
        (8000, [Port(port=8000)]),
        ({"target": 443, "published": 8443}, [Port(port=443)]),
        ({"target": 161, "protocol": "udp"}, [Port(port=161, protocol="udp")]),
    ],
)
def test_parse_port_keeps_the_container_side(item: object, expected: list[Port]) -> None:
    assert parse_port(item) == expected


def test_service_ports_merge_ports_and_expose_without_duplicates() -> None:
    service = {"ports": ["8080:80", "53:53/udp"], "expose": ["80", "9000"]}
    assert service_ports(service) == [
        Port(port=53, protocol="udp"),
        Port(port=80),
        Port(port=9000),
    ]


def test_local_files_cover_build_bind_and_env_file() -> None:
    service = {
        "build": {"context": "./app", "dockerfile": "Dockerfile.dev"},
        "volumes": [".:/app", "./conf:/etc/conf:ro", "data:/var/lib/data", "/anon"],
        "env_file": [".env", {"path": "extra.env"}],
    }
    found = [(f.kind, f.source) for f in local_files("web", service)]
    assert found == [
        ("build", "./app"),
        ("bind", "."),
        ("bind", "./conf"),
        ("env_file", ".env"),
        ("env_file", "extra.env"),
    ]


def test_named_and_long_syntax_volumes() -> None:
    service = {
        "volumes": [
            {"type": "volume", "source": "data", "target": "/data"},
            {"type": "bind", "source": "./x", "target": "/x"},
        ]
    }
    assert [f.source for f in local_files("web", service)] == ["./x"]


def test_no_local_files_for_an_image_only_service() -> None:
    assert local_files("web", {"image": "vulhub/app:1", "ports": ["80"]}) == []


def test_danger_reasons_follow_the_architecture_rules() -> None:
    service = {
        "privileged": True,
        "cap_add": ["NET_ADMIN"],
        "network_mode": "host",
        "pid": "host",
        "ipc": "host",
        "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
        "devices": ["/dev/fuse"],
    }
    reasons = [r.reason for r in danger_reasons("web", service)]
    assert reasons == [
        "privileged",
        "cap_add: NET_ADMIN",
        "devices",
        "network_mode: host",
        "pid: host",
        "ipc: host",
        "docker.sock mount",
    ]


def test_ordinary_service_is_not_dangerous() -> None:
    service = {"image": "redis", "privileged": False, "volumes": ["./conf:/etc/conf", "/anon"]}
    assert danger_reasons("cache", service) == []


def test_network_mode_is_dangerous_unless_it_joins_a_sibling() -> None:
    assert danger_reasons("app", {"network_mode": "service:db"}, frozenset({"db"})) == []
    for mode in ("bridge", "host", "service:other", "container:abc"):
        reasons = danger_reasons("app", {"network_mode": mode}, frozenset({"db"}))
        assert [r.reason for r in reasons] == [f"network_mode: {mode}"]


def test_unsupported_key_fails_the_build_with_the_environment_id() -> None:
    compose = "services:\n  web:\n    image: a\n    volumes_from: [db]\n"
    with pytest.raises(ParseError, match=r"vulhub/a/b: web: key 'volumes_from'"):
        parse_environment({"path": "a/b"}, compose, "", {}.get)


def test_interpolation_without_default_fails_the_build() -> None:
    compose = "services:\n  web:\n    image: a\n    user: ${UID}\n"
    with pytest.raises(ParseError, match="has no default"):
        parse_environment({"path": "a/b"}, compose, "", {}.get)


@pytest.mark.parametrize(
    ("dockerfile", "expected"),
    [
        ("FROM vulhub/tomcat:8.5\nCOPY app /app\n", "vulhub/tomcat:8.5"),
        ("from --platform=linux/amd64 python:3.6-alpine\n", "python:3.6-alpine"),
        ("FROM golang:1.22 AS build\nRUN make\nFROM alpine:3.20\n", "alpine:3.20"),
        ("FROM golang:1.22 AS build\nFROM build\n", None),
        ("ARG BASE=alpine\nFROM ${BASE}\n", None),
        ("RUN true\n", None),
    ],
)
def test_final_base_image(dockerfile: str, expected: str | None) -> None:
    assert final_base_image(dockerfile) == expected


def test_readme_summary_stops_before_setup_and_exploit() -> None:
    title, summary, references = parse_readme(README)
    assert title == "Example Remote Code Execution (CVE-2099-0001)"
    assert summary == (
        "Example is a web framework. See the docs. "
        "Versions before 1.2 let an attacker run commands."
    )
    assert references == ["https://example.org/advisory", "https://example.org/blog"]
    for leaked in ("docker", "payload", "Chinese", "following command"):
        assert leaked not in summary


def test_readme_descriptive_sections_feed_the_summary() -> None:
    readme = (
        "# Title\n\n## Reference link\n\nhttps://example.org/a\n\n"
        "## Rationale\n\n> The parser trusts input.\n\n## Setup\n\nRun it.\n"
    )
    assert parse_readme(readme) == ("Title", "The parser trusts input.", ["https://example.org/a"])


def test_readme_that_starts_with_setup_has_an_empty_summary() -> None:
    readme = "# Title\n\nBuild and run the vulnerable environment:\n\n```\nup\n```\n"
    assert parse_readme(readme) == ("Title", "", [])


def test_long_summary_is_cut_at_a_sentence() -> None:
    sentence = "This sentence is exactly fifty characters long ok. "
    _, summary, _ = parse_readme("# T\n\n" + sentence * 20)
    assert len(summary) <= 500
    assert summary.endswith(".")


def test_parse_environment_builds_an_entry() -> None:
    meta = {
        "name": "Example RCE",
        "cve": ["cve-2099-0001"],
        "app": "Example",
        "path": "example/CVE-2099-0001",
        "tags": ["RCE"],
    }
    files = {"Dockerfile": "FROM vulhub/example:1.0\n"}
    entry = parse_environment(meta, COMPOSE, README, files.get)
    assert entry.id == "vulhub/example/CVE-2099-0001"
    assert entry.product == "Example"
    assert entry.product_dir == "example"
    assert entry.cves == ["CVE-2099-0001"]
    assert [s.name for s in entry.services] == ["web", "db"]
    web, db = entry.services
    assert web.build_context == "."
    assert web.base_images == ["vulhub/example:1.0"]
    assert db.ports == [Port(port=3306)]
    assert [f.kind for f in entry.local_files] == ["build", "bind", "env_file"]
    assert not entry.image_only
    assert not entry.is_dangerous
    assert platform_image(web) == "vulhub/example:1.0"
    assert platform_image(db) == "mysql:5.7"


def test_with_platforms_fills_every_service() -> None:
    meta = {"name": "x", "app": "Example", "path": "example/x"}
    entry = parse_environment(meta, COMPOSE, README, {"Dockerfile": "FROM base:1\n"}.get)
    known = {"base:1": ["linux/amd64"], "mysql:5.7": ["linux/amd64", "linux/arm64"]}
    filled = with_platforms(entry, known.get)
    assert [s.platforms for s in filled.services] == [known["base:1"], known["mysql:5.7"]]
    assert filled.platforms == ["linux/amd64"]


def test_compose_without_services_is_an_error() -> None:
    with pytest.raises(ParseError):
        parse_environment({"path": "a/b"}, "version: '2'\n", "", {}.get)


def test_fallback_summary_uses_the_title_and_missing_cves() -> None:
    assert fallback_summary("Bash Shellshock (CVE-2014-6271)", ["CVE-2014-6271"]) == (
        "Bash Shellshock (CVE-2014-6271)."
    )
    assert fallback_summary("Example RCE", ["CVE-2099-0001", "CVE-2099-0002"]) == (
        "Example RCE. CVE-2099-0001, CVE-2099-0002."
    )
    assert fallback_summary("WordPress PwnScriptum.", []) == "WordPress PwnScriptum."


def test_empty_readme_summary_falls_back_to_the_title() -> None:
    meta = {"name": "x", "app": "Example", "path": "example/x", "cve": ["cve-2099-0001"]}
    readme = "# Example RCE\n\nBuild and run the vulnerable environment:\n\n```\nup\n```\n"
    entry = parse_environment(meta, COMPOSE, readme, {}.get)
    assert entry.summary == "Example RCE. CVE-2099-0001."

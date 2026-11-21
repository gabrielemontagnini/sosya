from pathlib import Path
from typing import Any

import pytest
from factories import index, services_of

from sosya.spec import Issue, RangeSpec, SpecError, check_catalog, errors, load_range, parse_range

DMZ_REDIS = """\
apiVersion: sosya/v1
name: dmz-redis
description: Struts2 in a DMZ, passwordless Redis only on the internal network
networks: [dmz, internal]
hosts:
  - name: web
    component: vulhub/struts2/s2-045
    networks: [dmz, internal]
    flag: /root/flag.txt
  - name: cache
    component: vulhub/redis/4-unacc
    networks: [internal]
attacker:
  networks: [dmz]
  internet: true
objectives:
  - Get a shell on web
"""


def data(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "apiVersion": "sosya/v1",
        "name": "lab",
        "networks": ["dmz", "internal"],
        "hosts": [
            {"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz", "internal"]},
            {"name": "cache", "component": "vulhub/redis/4-unacc", "networks": ["internal"]},
        ],
        "attacker": {"networks": ["dmz"]},
    }
    base.update(changes)
    return base


def check(spec: RangeSpec, platform: str | None = "linux/amd64", **kwargs: Any) -> list[Issue]:
    return check_catalog(spec, index(), host_platform=platform, services_of=services_of, **kwargs)


def test_load_range_from_a_file_or_a_directory(tmp_path: Path) -> None:
    (tmp_path / "range.yaml").write_text(DMZ_REDIS)
    for path in (tmp_path, tmp_path / "range.yaml"):
        spec = load_range(path)
        assert spec.name == "dmz-redis"
        assert spec.api_version == "sosya/v1"
        assert spec.attacker.internet is True
        assert [h.name for h in spec.hosts] == ["web", "cache"]


def test_round_trip_through_yaml(tmp_path: Path) -> None:
    spec = parse_range(data())
    (tmp_path / "range.yaml").write_text(spec.to_yaml())
    assert load_range(tmp_path) == spec
    assert spec.to_yaml().startswith("apiVersion: sosya/v1\n")


def test_missing_and_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(SpecError, match="does not exist"):
        load_range(tmp_path)
    (tmp_path / "range.yaml").write_text("hosts: [unclosed\n")
    with pytest.raises(SpecError, match="not valid YAML"):
        load_range(tmp_path)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"apiVersion": "sosya/v2"}, "apiVersion"),
        ({"name": "Bad_Name"}, "name: String should match pattern"),
        ({"extra": 1}, "extra: Extra inputs are not permitted"),
        ({"networks": ["dmz", "dmz", "internal"]}, "duplicate networks: dmz"),
        ({"networks": ["dmz", "internal", "egress"]}, "reserved by Sosya: egress"),
        ({"networks": ["dmz", "internal", "spare"]}, "declared but not used: spare"),
        ({"attacker": {"networks": ["lan"]}}, "attacker joins undeclared networks: lan"),
        ({"attacker": {"networks": []}}, "attacker.networks"),
        ({"hosts": []}, "hosts: List should have at least 1 item"),
    ],
)
def test_structural_errors(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(SpecError, match=message):
        parse_range(data(**changes))


def test_host_errors_name_the_field() -> None:
    hosts = data()["hosts"]
    hosts[1] = {**hosts[1], "networks": ["lan"]}
    with pytest.raises(SpecError, match="host cache joins undeclared networks: lan"):
        parse_range(data(hosts=hosts))
    hosts[1] = {**hosts[1], "networks": ["internal"], "flag": "flag.txt"}
    with pytest.raises(SpecError, match=r"hosts\[1\]: .*absolute path"):
        parse_range(data(hosts=hosts))
    hosts[1] = {**hosts[1], "flag": "/root/../etc/shadow"}
    with pytest.raises(SpecError, match="absolute path"):
        parse_range(data(hosts=hosts))
    hosts[1] = {**hosts[1], "flag": None, "name": "attacker"}
    with pytest.raises(SpecError, match="'attacker' is reserved"):
        parse_range(data(hosts=hosts))
    with pytest.raises(SpecError, match="duplicate host names: web"):
        parse_range(data(hosts=[hosts[0], hosts[0]]))


def test_attacker_must_reach_something() -> None:
    hosts = [{"name": "cache", "component": "vulhub/redis/4-unacc", "networks": ["internal"]}]
    attacker = {"networks": ["dmz"]}
    with pytest.raises(SpecError, match="shares no network"):
        parse_range(data(hosts=hosts, attacker=attacker, networks=["dmz", "internal"]))


def test_valid_range_has_no_issues() -> None:
    assert check(parse_range(data())) == []


def test_unknown_component_suggests_close_ids() -> None:
    hosts = data()["hosts"]
    hosts[0] = {**hosts[0], "component": "vulhub/struts2/s2-046"}
    [issue] = check(parse_range(data(hosts=hosts)))
    assert issue.level == "error"
    assert issue.host == "web"
    assert "not in the catalog" in issue.message
    assert "vulhub/struts2/s2-045" in issue.message


def test_unknown_service_is_an_error() -> None:
    hosts = data()["hosts"]
    hosts[0] = {**hosts[0], "service": "tomcat"}
    [issue] = check(parse_range(data(hosts=hosts)))
    assert "has no service 'tomcat' (it has struts2)" in issue.message


def test_dangerous_environment_needs_consent() -> None:
    hosts = data()["hosts"]
    hosts[0] = {**hosts[0], "component": "vulhub/docker/unauthorized-rce"}
    spec = parse_range(data(hosts=hosts))
    [refused] = check(spec)
    assert refused.level == "error"
    assert "docker: privileged" in refused.message
    assert "--allow-privileged" in refused.message
    [allowed] = check(spec, allow_privileged=True)
    assert allowed.level == "warning"
    assert "docker: privileged" in allowed.message


@pytest.mark.parametrize(
    ("component", "platform", "level", "text"),
    [
        ("vulhub/struts2/s2-045", "linux/arm64", "warning", "only under emulation"),
        ("vulhub/arm/only", "linux/amd64", "error", "cannot run on linux/amd64"),
        ("vulhub/arm/only", "linux/arm64", None, ""),
        ("vulhub/broken/image", "linux/amd64", "error", "cannot be pulled"),
    ],
)
def test_platforms(component: str, platform: str, level: str | None, text: str) -> None:
    hosts = data()["hosts"]
    hosts[0] = {**hosts[0], "component": component}
    issues = [
        i for i in check(parse_range(data(hosts=hosts)), platform=platform) if i.host == "web"
    ]
    if level is None:
        assert issues == []
    else:
        [issue] = issues
        assert (issue.level, issue.host) == (level, "web")
        assert text in issue.message


def test_platform_check_is_skipped_without_an_engine() -> None:
    hosts = data()["hosts"]
    hosts[0] = {**hosts[0], "component": "vulhub/arm/only"}
    assert check(parse_range(data(hosts=hosts)), platform=None) == []


def test_ambiguous_dns_name_is_an_error() -> None:
    # `wp` uses `mysql` as an internal alias; a host named `mysql` on the same segment as
    # wp's main service would make `mysql` mean two containers.
    hosts = [
        {"name": "wp", "component": "vulhub/wordpress/pwnscriptum", "networks": ["dmz"]},
        {"name": "mysql", "component": "vulhub/redis/4-unacc", "networks": ["dmz"]},
    ]
    issues = errors(check(parse_range(data(hosts=hosts, networks=["dmz"]))))
    assert len(issues) == 1
    assert "DNS name 'mysql' is ambiguous for wp" in issues[0].message


def test_generated_name_clash_is_an_error() -> None:
    hosts = [
        {"name": "wp", "component": "vulhub/wordpress/pwnscriptum", "networks": ["dmz"]},
        {"name": "wp-mysql", "component": "vulhub/redis/4-unacc", "networks": ["dmz"]},
    ]
    messages = [i.message for i in check(parse_range(data(hosts=hosts, networks=["dmz"])))]
    assert "service name 'wp-mysql' is generated twice (wp, wp-mysql)" in messages


def test_private_network_name_clash_is_an_error() -> None:
    hosts = [{"name": "wp", "component": "vulhub/wordpress/pwnscriptum", "networks": ["wp-net"]}]
    spec = parse_range(data(hosts=hosts, networks=["wp-net"], attacker={"networks": ["wp-net"]}))
    assert "network name 'wp-net' is generated twice" in [i.message for i in check(spec)]

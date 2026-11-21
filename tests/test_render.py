from pathlib import Path
from typing import Any

import pytest
import yaml
from snapshot import assert_snapshot

from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex, Entry
from sosya.catalog.rules import HOST_LEVEL_KEYS, SAFE_KEYS
from sosya.render import RenderError, dump, render
from sosya.spec import RangeSpec, parse_range

ATTACKER_IMAGE = "ghcr.io/gabrielemontagnini/sosya-attacker:test"
VULHUB = Path("/cache/vulhub")
FILES = Path("/work/.sosya/ranges/lab/files")
# Keys a rendered target may carry: the allowlist, plus what the renderer adds.
RENDERED_KEYS = set(SAFE_KEYS) - {"labels"} | {
    "labels",
    "platform",
    "networks",
    "pids_limit",
    "logging",
}


@pytest.fixture(scope="module")
def index() -> CatalogIndex:
    return load_index()


def source_dir(entry: Entry) -> Path:
    return VULHUB / entry.path


def spec(
    hosts: list[dict[str, Any]],
    networks: list[str],
    attacker: list[str],
    internet: bool = True,
    name: str = "lab",
) -> RangeSpec:
    return parse_range(
        {
            "apiVersion": "sosya/v1",
            "name": name,
            "networks": networks,
            "hosts": hosts,
            "attacker": {"networks": attacker, "internet": internet},
        }
    )


def do_render(range_spec: RangeSpec, index: CatalogIndex, **kwargs: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "services_of": load_services,
        "attacker_image": ATTACKER_IMAGE,
        "engine_platform": "linux/amd64",
        "source_dir": source_dir,
        "files_dir": FILES,
    }
    options.update(kwargs)
    return render(range_spec, index, **options)


DMZ_REDIS = [
    {"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz", "internal"]},
    {"name": "cache", "component": "vulhub/redis/4-unacc", "networks": ["internal"]},
]


def test_dmz_redis_snapshot(index: CatalogIndex) -> None:
    compose = do_render(spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"], name="dmz-redis"), index)
    assert_snapshot("dmz-redis.yml", dump(compose))


def test_multi_service_component_snapshot(index: CatalogIndex) -> None:
    hosts = [{"name": "blog", "component": "vulhub/wordpress/pwnscriptum", "networks": ["dmz"]}]
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index)
    assert_snapshot("wordpress.yml", dump(compose))
    assert compose["services"]["blog-mysql"]["networks"] == {"blog-net": {"aliases": ["mysql"]}}
    assert compose["services"]["blog"]["depends_on"] == ["blog-mysql"]


def test_local_files_snapshot(index: CatalogIndex) -> None:
    hosts = [{"name": "fpm", "component": "vulhub/php/CVE-2019-11043", "networks": ["dmz"]}]
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index)
    assert_snapshot("php-fpm-binds.yml", dump(compose))
    for service in compose["services"].values():
        for volume in service.get("volumes", []):
            assert volume.startswith(f"{FILES}/fpm/"), volume


def test_attacker_without_internet_snapshot(index: CatalogIndex) -> None:
    compose = do_render(spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"], internet=False), index)
    assert_snapshot("no-internet.yml", dump(compose))
    assert "egress" not in compose["networks"]
    assert compose["services"]["attacker"]["networks"] == {"dmz": {}}


def test_build_and_env_file_use_the_shared_source(index: CatalogIndex) -> None:
    hosts = [{"name": "mail", "component": "vulhub/jira/CVE-2019-11581", "networks": ["dmz"]}]
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index)
    smtpd = compose["services"]["mail-smtpd"]
    assert smtpd["build"] == {
        "context": str(VULHUB / "jira/CVE-2019-11581"),
        "dockerfile": "Dockerfile.smtpd",
    }
    jira = compose["services"]["mail"]
    assert "links" not in jira
    assert compose["services"]["mail-smtpd"]["networks"]["mail-net"] == {"aliases": ["smtpd"]}


def test_interpolations_resolve_to_their_defaults(index: CatalogIndex) -> None:
    hosts = [{"name": "air", "component": "vulhub/airflow/CVE-2020-11978", "networks": ["dmz"]}]
    text = dump(do_render(spec(hosts, ["dmz"], ["dmz"]), index))
    assert "AIRFLOW_UID" not in text
    assert "user: 50000:50000" in text
    assert "$${HOSTNAME}" in text  # Compose's escaped dollar is kept


def test_container_name_is_dropped(index: CatalogIndex) -> None:
    hosts = [{"name": "aio", "component": "vulhub/python/CVE-2024-23334", "networks": ["dmz"]}]
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index, engine_platform="linux/arm64")
    assert "container_name" not in compose["services"]["aio"]
    assert compose["services"]["aio"]["platform"] == "linux/arm64"


def test_platform_is_native_when_available_else_amd64(index: CatalogIndex) -> None:
    hosts = [{"name": "panel", "component": "vulhub/1panel/CVE-2024-39907", "networks": ["dmz"]}]
    native = do_render(spec(hosts, ["dmz"], ["dmz"]), index, engine_platform="linux/arm64")
    assert native["services"]["panel"]["platform"] == "linux/arm64"
    emulated = do_render(
        spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"]), index, engine_platform="linux/arm64"
    )
    assert emulated["services"]["web"]["platform"] == "linux/amd64"
    assert "platform" not in emulated["services"]["attacker"]


def test_dangerous_environment_needs_consent(index: CatalogIndex) -> None:
    hosts = [{"name": "dock", "component": "vulhub/docker/unauthorized-rce", "networks": ["dmz"]}]
    with pytest.raises(RenderError, match="--allow-privileged"):
        do_render(spec(hosts, ["dmz"], ["dmz"]), index)
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index, allow_privileged=True)
    assert compose["services"]["dock"]["privileged"] is True


def test_reserved_labels_are_refused(index: CatalogIndex) -> None:
    definitions = {"struts2": {"image": "a", "ports": ["80"], "labels": ["sosya.range=evil"]}}
    hosts = [{"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz"]}]
    with pytest.raises(RenderError, match=r"label 'sosya\.range' is reserved"):
        do_render(spec(hosts, ["dmz"], ["dmz"]), index, services_of=lambda _: definitions)


def test_unsupported_key_is_refused_with_the_environment_id(index: CatalogIndex) -> None:
    definitions = {"struts2": {"image": "a", "ports": ["80"], "volumes_from": ["x"]}}
    hosts = [{"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz"]}]
    with pytest.raises(RenderError, match=r"vulhub/struts2/s2-045: service struts2: key"):
        do_render(spec(hosts, ["dmz"], ["dmz"]), index, services_of=lambda _: definitions)


def test_restart_never_outlives_the_daemon(index: CatalogIndex) -> None:
    definitions = {"struts2": {"image": "a", "ports": ["80"], "restart": "always"}}
    hosts = [{"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz"]}]
    compose = do_render(spec(hosts, ["dmz"], ["dmz"]), index, services_of=lambda _: definitions)
    assert compose["services"]["web"]["restart"] == "on-failure"


# --- properties over the whole catalog -------------------------------------------------------


def _single(entry: Entry) -> RangeSpec:
    hosts = [{"name": "target", "component": entry.id, "networks": ["lab"]}]
    return spec(hosts, ["lab"], ["lab"])


def _assert_isolated(compose: dict[str, Any], entry: Entry) -> None:
    text = dump(compose)
    assert "ports:" not in text, entry.id
    assert "container_name" not in text, entry.id
    assert "links:" not in text, entry.id
    assert "${" not in text.replace("$${", ""), entry.id
    for name, network in compose["networks"].items():
        if name == "egress":
            continue
        assert network["internal"] is True, (entry.id, name)
        assert network["enable_ipv6"] is False, (entry.id, name)
        assert network["driver_opts"] == {
            "com.docker.network.bridge.gateway_mode_ipv4": "isolated"
        }, (entry.id, name)
    attacker = compose["services"]["attacker"]
    assert attacker["sysctls"] == {"net.ipv4.ip_forward": "0"}
    for name, service in compose["services"].items():
        if name == "attacker":
            continue
        assert "egress" not in service.get("networks", {}), (entry.id, name)
        extra = set(service) - RENDERED_KEYS
        if entry.is_dangerous:
            extra -= HOST_LEVEL_KEYS
        assert not extra, (entry.id, name, extra)
        for volume in service.get("volumes", []):
            source = volume.split(":")[0]
            if source.startswith("/"):
                assert source.startswith(f"{FILES}/target"), (entry.id, volume)
        build = service.get("build")
        if build:
            assert build["context"].startswith(str(VULHUB / entry.path)), entry.id


def test_every_catalog_environment_renders_isolated(index: CatalogIndex) -> None:
    for entry in index.entries:
        range_spec = _single(entry)
        if entry.is_dangerous:
            with pytest.raises(RenderError, match="--allow-privileged"):
                do_render(range_spec, index, engine_platform=None)
            compose = do_render(range_spec, index, engine_platform=None, allow_privileged=True)
        else:
            compose = do_render(range_spec, index, engine_platform=None)
        _assert_isolated(compose, entry)
        assert yaml.safe_load(dump(compose)) == compose

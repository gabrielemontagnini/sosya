"""Isolation checks on a real range, ported from the network spike (docs/architecture.md).

The range is the gallery's `dmz-redis`, rendered and started by the real runtime. Probes from the
targets run in their network namespace (`docker run --network container:<id>`), so they do not
depend on the tools inside the target images. Network checks run by DNS name and by IP.

Run with `uv run pytest -m docker`. Needs Docker Engine 28+, the attacker box image (built from
the packaged Dockerfile if it cannot be pulled) and internet access for the attacker checks.
"""

import json
import socket
import subprocess
import time
from collections.abc import Iterator

import pytest

from sosya import gallery, runtime
from sosya.runtime.docker import Docker

pytestmark = pytest.mark.docker

EXAMPLE = gallery.path("dmz-redis")
PROJECT = "sosya-dmz-redis"
PROBE_IMAGE = "alpine:3.20"


def docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
    )


class Range:
    def __init__(self) -> None:
        containers = Docker().containers(PROJECT)
        self.ids = {c.service: c.id for c in containers}

    def ip(self, service: str, network: str) -> str:
        template = f'{{{{(index .NetworkSettings.Networks "{PROJECT}_{network}").IPAddress}}}}'
        return docker("inspect", "-f", template, self.ids[service]).stdout.strip()

    def attacker(self, command: str) -> bool:
        return docker("exec", self.ids["attacker"], "sh", "-c", command).returncode == 0

    def probe(self, service: str, command: str) -> bool:
        network = f"container:{self.ids[service]}"
        return (
            docker("run", "--rm", "--network", network, PROBE_IMAGE, "sh", "-c", command).returncode
            == 0
        )


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Range]:
    workspace = runtime.Workspace(tmp_path_factory.mktemp("work") / ".sosya")
    if docker("image", "inspect", PROBE_IMAGE).returncode != 0:
        assert docker("pull", "--quiet", PROBE_IMAGE, timeout=300).returncode == 0
    assert EXAMPLE is not None
    runtime.up(
        EXAMPLE, report=lambda level, text: None, confirm=lambda lines: False, workspace=workspace
    )
    try:
        lab = Range()
        for _ in range(60):  # Tomcat takes a while after the container is running
            if lab.attacker("curl -s -o /dev/null http://web:8080/"):
                break
            time.sleep(2)
        yield lab
    finally:
        runtime.down("dmz-redis", report=lambda level, text: None, workspace=workspace)


def _reachable_from_host(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=3):
            return True
    except OSError:
        return False


# --- 1 host -> targets -----------------------------------------------------------------------


@pytest.mark.parametrize("service", ["web", "cache"])
def test_targets_publish_no_ports(lab: Range, service: str) -> None:
    data = json.loads(docker("inspect", lab.ids[service]).stdout)[0]
    assert not data["HostConfig"].get("PortBindings")
    assert all(not bindings for bindings in (data["NetworkSettings"]["Ports"] or {}).values())


@pytest.mark.parametrize(
    ("service", "network", "port"),
    [("web", "dmz", 8080), ("web", "internal", 8080), ("cache", "internal", 6379)],
)
def test_host_cannot_reach_target_ips(lab: Range, service: str, network: str, port: int) -> None:
    ip = lab.ip(service, network)
    assert ip
    assert not _reachable_from_host(ip, port)


# --- 2 attacker -> targets, pivot, segmentation ----------------------------------------------


def test_attacker_reaches_web_by_name_and_ip(lab: Range) -> None:
    assert lab.attacker("curl -sf -m 5 -o /dev/null http://web:8080/")
    assert lab.attacker(f"curl -sf -m 5 -o /dev/null http://{lab.ip('web', 'dmz')}:8080/")


def test_web_pivots_to_cache_by_name_and_ip(lab: Range) -> None:
    for target in ("cache", lab.ip("cache", "internal")):
        assert lab.probe("web", f"printf 'PING\\r\\n' | nc -w 3 {target} 6379 | grep -q PONG")


def test_attacker_cannot_reach_the_internal_segment(lab: Range) -> None:
    assert not lab.attacker("nc -z -w 3 cache 6379")
    assert not lab.attacker(f"nc -z -w 3 {lab.ip('cache', 'internal')} 6379")
    assert not lab.attacker(f"nc -z -w 3 {lab.ip('web', 'internal')} 8080")


def test_attacker_does_not_forward_packets(lab: Range) -> None:
    assert lab.attacker('[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ]')


# --- 3 targets -> internet -------------------------------------------------------------------


@pytest.mark.parametrize("service", ["web", "cache"])
@pytest.mark.parametrize(
    "command",
    [
        "nslookup -timeout=3 example.com",
        "nc -z -w 3 1.1.1.1 443",
        "nc -z -w 3 2606:4700::1111 443",
        "wget -q -T 3 -O /dev/null http://example.com",
        "ip route | grep -q ^default",
    ],
    ids=["dns", "tcp", "tcp6", "http", "default-route"],
)
def test_targets_have_no_internet(lab: Range, service: str, command: str) -> None:
    assert not lab.probe(service, command)


# --- 4 attacker -> internet ------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["getent hosts example.com", "curl -sfI -m 10 https://example.com", "nc -z -w 3 1.1.1.1 443"],
    ids=["dns", "https", "tcp"],
)
def test_attacker_has_internet(lab: Range, command: str) -> None:
    assert lab.attacker(command)

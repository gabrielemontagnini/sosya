"""Isolation checks on a real range: `sosya.validate` on the gallery's `dmz-redis`.

Every check (reach, segmentation, no internet for targets, host isolation, flags) comes from
`sosya.validate`, so users' ranges get exactly what CI checks here. Only the checks specific to
dmz-redis stay in this file: the pivot from web to cache, and no published ports.

Run with `uv run pytest -m docker`. Needs Docker Engine 28+, the attacker box image (built from
the packaged Dockerfile if it cannot be pulled) and internet access for the attacker checks.
"""

import json
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from sosya import attacker, gallery, runtime
from sosya.runtime.docker import Docker
from sosya.validate import Check, failures, validate
from sosya.validate.probes import tcp

pytestmark = pytest.mark.docker

EXAMPLE = gallery.path("dmz-redis")
PROJECT = "sosya-dmz-redis"


def docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
    )


@dataclass
class Lab:
    ids: dict[str, str]
    checks: list[Check]

    def probe(self, service: str, command: str) -> bool:
        """Run a command in a target's network namespace, with the attacker image."""
        network = f"container:{self.ids[service]}"
        args = ["run", "--rm", "--network", network, "--entrypoint", "sh", attacker.image()]
        return docker(*args, "-c", command).returncode == 0


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    workspace = runtime.Workspace(tmp_path_factory.mktemp("work") / ".sosya")
    assert EXAMPLE is not None
    runtime.up(
        EXAMPLE, report=lambda level, text: None, confirm=lambda lines: False, workspace=workspace
    )
    try:
        ids = {c.service: c.id for c in Docker().containers(PROJECT)}
        yield Lab(ids, validate("dmz-redis", workspace=workspace))
    finally:
        runtime.down("dmz-redis", report=lambda level, text: None, workspace=workspace)


def test_every_validation_check_passes(lab: Lab) -> None:
    assert failures(lab.checks) == []
    assert not [c for c in lab.checks if not c.ok], "warnings: the attacker needs internet here"


@pytest.mark.parametrize(
    "group",
    ["service", "reach", "segmentation", "no internet", "host isolation", "attacker", "flag"],
)
def test_validation_covers(lab: Lab, group: str) -> None:
    assert any(c.group == group for c in lab.checks)


def test_validation_checks_the_spike_cases(lab: Lab) -> None:
    targets = {(c.group, c.target) for c in lab.checks}
    assert ("reach", "web:8080") in targets
    assert ("segmentation", "cache (dns)") in targets
    for service in ("web", "cache"):
        for name in ("dns", "tcp", "tcp6", "http", "default route"):
            assert ("no internet", f"{service} ({name})") in targets


@pytest.mark.parametrize("service", ["web", "cache"])
def test_targets_publish_no_ports(lab: Lab, service: str) -> None:
    data = json.loads(docker("inspect", lab.ids[service]).stdout)[0]
    assert not data["HostConfig"].get("PortBindings")
    assert all(not bindings for bindings in (data["NetworkSettings"]["Ports"] or {}).values())


def test_web_pivots_to_cache(lab: Lab) -> None:
    assert lab.probe("web", "printf 'PING\\r\\n' | nc -w 3 cache 6379 | grep -q PONG")
    assert lab.probe("web", tcp("cache", 6379))


def test_the_attacker_tools_run_in_the_box(lab: Lab) -> None:
    """Without NET_ADMIN, a binary with that file capability does not even start."""
    box = lab.ids["attacker"]
    for command in ("nmap --version", "socat -V", "redis-cli --version", "curl --version"):
        proc = docker("exec", box, "sh", "-c", command)
        assert proc.returncode == 0, f"{command}: {proc.stderr}"

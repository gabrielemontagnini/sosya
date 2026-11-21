"""`sosya up --proxy --expose` on real ranges: localhost only, and no way out for targets.

Every check comes from `sosya.validate` (group `exposure`), so users' ranges get what CI checks
here. This file adds what a person would do by hand: a real HTTP request through the proxy and
through a forward, and the same range without internet.

Run with `uv run pytest -m docker`. Needs Docker Engine 28+ and the attacker image (set
`SOSYA_ATTACKER_IMAGE` to an image built from this commit's Dockerfile).
"""

import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from sosya import gallery, runtime
from sosya.exposure import Exposure, Forward
from sosya.validate import Check, failures, validate

pytestmark = pytest.mark.docker


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def quiet(level: str, text: str) -> None:
    pass


def start(path: Path, name: str, exposure: Exposure, root: Path) -> list[Check]:
    workspace = runtime.Workspace(root / ".sosya")
    runtime.up(
        path, report=quiet, confirm=lambda lines: False, workspace=workspace, exposure=exposure
    )
    return validate(name, workspace=workspace)


def stop(name: str, root: Path) -> None:
    runtime.down(name, report=quiet, workspace=runtime.Workspace(root / ".sosya"))


def curl(*args: str) -> str:
    proc = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout


@pytest.fixture(scope="module")
def online(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Exposure, list[Check]]]:
    root = tmp_path_factory.mktemp("online")
    exposure = Exposure(free_port(), (Forward("web", 8080, free_port()),))
    path = gallery.path("dmz-redis")
    assert path is not None
    try:
        yield exposure, start(path, "dmz-redis", exposure, root)
    finally:
        stop("dmz-redis", root)


@pytest.fixture(scope="module")
def offline(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Exposure, list[Check]]]:
    root = tmp_path_factory.mktemp("offline")
    path = gallery.path("dmz-redis")
    assert path is not None
    source = (path / "range.yaml").read_text()
    source = source.replace("name: dmz-redis", "name: dmz-offline")
    source = source.replace("internet: true", "internet: false")
    (root / "range.yaml").write_text(source)
    exposure = Exposure(free_port())
    try:
        yield exposure, start(root / "range.yaml", "dmz-offline", exposure, root)
    finally:
        stop("dmz-offline", root)


def test_every_check_passes_with_proxy_and_expose(online: tuple[Exposure, list[Check]]) -> None:
    exposure, checks = online
    assert failures(checks) == []
    targets = {c.target for c in checks if c.group == "exposure"}
    assert "relay ports" in targets and f"[::1]:{exposure.proxy_port}" in targets
    assert any(t.startswith("web → relay") for t in targets)
    assert any(t.startswith("cache → attacker") for t in targets)


def test_a_browser_reaches_the_range_through_the_proxy(
    online: tuple[Exposure, list[Check]],
) -> None:
    exposure, _ = online
    proxy = f"127.0.0.1:{exposure.proxy_port}"
    assert curl("--socks5-hostname", proxy, "http://web:8080/") == "200"
    # Segmentation holds through the proxy: cache is not on the attacker box's network.
    assert curl("--socks5-hostname", proxy, "http://cache:6379/") == "000"
    (forward,) = exposure.forwards
    assert curl(f"http://127.0.0.1:{forward.local}/") == "200"


def test_without_internet_the_proxy_gives_none(offline: tuple[Exposure, list[Check]]) -> None:
    exposure, checks = offline
    assert failures(checks) == []
    targets = {c.target for c in checks if c.group == "exposure"}
    assert "proxy → 1.1.1.1:443" in targets and "proxy → web:8080" in targets
    proxy = f"127.0.0.1:{exposure.proxy_port}"
    assert curl("--socks5-hostname", proxy, "https://example.com/") == "000"
    assert curl("--socks5-hostname", proxy, "http://web:8080/") == "200"

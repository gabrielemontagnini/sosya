"""`--proxy` and `--expose`: parsing, checks, rendering, the runtime and validation, no Docker."""

import socket
import socketserver
import threading
from pathlib import Path
from typing import Any, ClassVar

import pytest
from snapshot import assert_snapshot
from test_render import DMZ_REDIS, do_render, spec
from test_runtime import FakeDocker, container, start
from test_validate import Lab, by, inspected

from sosya import exposure as ex
from sosya import runtime, topology
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex
from sosya.render import RenderError, dump
from sosya.runtime import state as state_store
from sosya.validate import failures, socks
from sosya.validate import probes as probe_module

BOTH = ex.Exposure(1080, (ex.Forward("web", 8080, 18080),))


@pytest.fixture(scope="module")
def index() -> CatalogIndex:
    return load_index()


# --- parsing and checks --------------------------------------------------------------------


def test_parse_expose() -> None:
    assert ex.parse_expose("web:8080") == ex.Forward("web", 8080, 8080)
    assert ex.parse_expose("web:8080:18080") == ex.Forward("web", 8080, 18080)
    for bad in ("web", "web:http", ":80", "web:80:0", "web:70000", "a:1:2:3"):
        with pytest.raises(ex.ExposureError):
            ex.parse_expose(bad)


def test_problems_need_a_service_the_attacker_reaches() -> None:
    plan = topology.build(spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"]), load_services)
    assert ex.problems(BOTH, plan) == []
    unreachable = ex.Exposure(None, (ex.Forward("cache", 6379, 6379),))
    (problem,) = ex.problems(unreachable, plan)
    assert "does not reach cache" in problem
    (problem,) = ex.problems(ex.Exposure(None, (ex.Forward("db", 1, 1),)), plan)
    assert "no service db" in problem
    twice = ex.Exposure(8080, (ex.Forward("web", 8080, 8080),))
    assert "used twice: 8080" in ex.problems(twice, plan)[0]


def test_busy_ports_are_found() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        assert ex.busy([port]) == [port]


def test_state_round_trip() -> None:
    assert ex.Exposure.from_state(**BOTH.state()) == BOTH


# --- rendering -----------------------------------------------------------------------------


def test_render_with_proxy_and_expose(index: CatalogIndex) -> None:
    range_spec = spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"], name="dmz-redis")
    compose = do_render(range_spec, index, exposure=BOTH)
    assert_snapshot("dmz-redis-proxy.yml", dump(compose))
    services, networks = compose["services"], compose["networks"]
    published = {key: s["ports"] for key, s in services.items() if "ports" in s}
    assert published == {"relay": ["127.0.0.1:1080:1080", "127.0.0.1:18080:18080"]}
    assert set(services["relay"]["networks"]) == {"relay", "proxy"}
    assert services["relay"]["sysctls"] == {"net.ipv4.ip_forward": "0"}
    assert services["attacker-relay"]["network_mode"] == "service:attacker"
    assert services["attacker-relay"]["command"] == [
        "sosya-forward",
        "--socks",
        "1080",
        "18080=web:8080",
    ]
    assert services["attacker"]["networks"]["relay"] == {"aliases": ["attacker-link"]}
    for key in ("web", "cache", "web", "attacker"):
        assert not set(services[key].get("networks", {})) & {"proxy"}
    for key in ("web", "cache"):
        assert "relay" not in services[key]["networks"]
    assert networks["relay"]["internal"] is True
    assert networks["proxy"] == {"enable_ipv6": False, "labels": {"sosya.range": "dmz-redis"}}


def test_render_without_internet_keeps_the_attacker_off_open_networks(
    index: CatalogIndex,
) -> None:
    range_spec = spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"], internet=False)
    compose = do_render(range_spec, index, exposure=ex.Exposure(1080))
    assert_snapshot("no-internet-proxy.yml", dump(compose))
    attacker = compose["services"]["attacker"]["networks"]
    assert set(attacker) == {"dmz", "relay"}
    assert all(compose["networks"][name].get("internal") for name in attacker)


def test_render_refuses_an_expose_the_attacker_cannot_reach(index: CatalogIndex) -> None:
    unreachable = ex.Exposure(None, (ex.Forward("cache", 6379, 6379),))
    with pytest.raises(RenderError, match="does not reach cache"):
        do_render(spec(DMZ_REDIS, ["dmz", "internal"], ["dmz"]), index, exposure=unreachable)


def test_reserved_names() -> None:
    with pytest.raises(Exception, match="reserved"):
        spec(
            [{"name": "relay", "component": "vulhub/redis/4-unacc", "networks": ["x"]}],
            ["x"],
            ["x"],
        )
    with pytest.raises(Exception, match="reserved"):
        spec(
            [{"name": "a", "component": "vulhub/redis/4-unacc", "networks": ["relay"]}],
            ["relay"],
            ["relay"],
        )


# --- runtime -------------------------------------------------------------------------------


def test_up_records_the_exposure_and_warns(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ex, "busy", lambda ports, host="127.0.0.1": [])
    record, log = start(range_dir, workspace, fake, exposure=BOTH)
    assert record.proxy_port == 1080
    assert record.exposes == [{"target": "web", "port": 8080, "local": 18080}]
    saved = state_store.load(workspace.root)["dmz-redis"]
    assert saved.proxy_port == 1080 and saved.exposes == record.exposes
    assert ("warn", "publishing web:8080 on 127.0.0.1:18080 (localhost only)") in log.lines
    assert any("proxy socks5h://127.0.0.1:1080" in text for _, text in log.lines)
    pulls = [argv[-1] for argv in fake.commands("pull")]
    assert runtime.attacker.image() not in pulls


def test_up_refuses_ports_in_use(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ex, "busy", lambda ports, host="127.0.0.1": [1080])
    with pytest.raises(runtime.HostEnvironmentError, match=r"127\.0\.0\.1:1080 already in use"):
        start(range_dir, workspace, fake, exposure=BOTH)
    assert fake.commands("compose") == []


def test_up_again_keeps_its_own_ports(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ex, "busy", lambda ports, host="127.0.0.1": [1080])
    fake.containers = [container("relay", role="relay")]
    start(range_dir, workspace, fake, exposure=BOTH)  # its own relay holds the port


def test_up_refuses_an_unreachable_expose(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    unreachable = ex.Exposure(None, (ex.Forward("cache", 6379, 6379),))
    with pytest.raises(runtime.RangeError, match="does not reach cache"):
        start(range_dir, workspace, fake, exposure=unreachable)


# --- validation ----------------------------------------------------------------------------

RELAY_IPS = {"relay": "10.0.7.2", "proxy": "10.0.8.2"}


class ExposedLab(Lab):
    def __init__(self, tmp_path: Path) -> None:
        super().__init__(tmp_path)
        record = state_store.load(self.workspace.root)["dmz-redis"]
        state_store.record(
            self.workspace.root,
            state_store.RangeState(
                **{**record.__dict__, "proxy_port": 1080, "exposes": [BOTH.forwards[0].__dict__]}
            ),
        )
        relay = inspected("attacker", role="relay")
        relay["Id"] = "relay0000000" + "0" * 52
        labels = relay["Config"]["Labels"]
        labels["com.docker.compose.service"] = labels["sosya.host"] = "relay"
        relay["State"]["Health"] = {"Status": "healthy"}
        relay["NetworkSettings"]["Networks"] = {
            f"sosya-dmz-redis_{net}": {"IPAddress": ip} for net, ip in RELAY_IPS.items()
        }
        relay["HostConfig"]["PortBindings"] = {
            "1080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1080"}],
            "18080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}],
        }
        forwarder = inspected("attacker", role="relay")
        forwarder["Id"] = "forwarder000" + "0" * 52
        labels = forwarder["Config"]["Labels"]
        labels["com.docker.compose.service"] = labels["sosya.host"] = "attacker-relay"
        forwarder["State"]["Health"] = {"Status": "healthy"}
        forwarder["NetworkSettings"]["Networks"] = {}
        self.fake.containers += [relay, forwarder]
        self.host_reaches: set[tuple[str, int]] = {("127.0.0.1", 1080), ("127.0.0.1", 18080)}
        self.proxy_reaches: set[tuple[str, int]] = {("web", 8080)}

    def run(self, **kwargs: Any):
        from sosya.validate import validate

        return validate(
            "dmz-redis",
            workspace=self.workspace,
            docker=runtime.Docker(runner=self.fake),
            ready_timeout=kwargs.pop("ready_timeout", 0),
            **kwargs,
        )


@pytest.fixture
def exposed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ExposedLab:
    lab = ExposedLab(tmp_path)

    def host_connects(ip: str, port: int, timeout: float = 2.0) -> bool:
        return (ip, port) in lab.host_reaches

    monkeypatch.setattr(probe_module, "host_connects", host_connects)
    monkeypatch.setattr(probe_module, "host_addresses", lambda: ["192.168.1.20", "2001:db8::20"])
    monkeypatch.setattr(probe_module, "forward_answers", lambda port, host="127.0.0.1": True)
    monkeypatch.setattr(
        socks, "connect", lambda proxy, host, port, timeout=5.0: (host, port) in lab.proxy_reaches
    )
    return lab


def test_an_exposed_range_passes_every_check(exposed: ExposedLab) -> None:
    checks = exposed.run()
    assert failures(checks) == []
    exposure = by(checks, "exposure")
    for target in (
        "relay",
        "attacker-relay",
        "relay ports",
        "127.0.0.1:1080",
        "[::1]:1080",
        "192.168.1.20:18080",
        "[2001:db8::20]:1080",
        "proxy → web:8080",
        "127.0.0.1:18080 → web:8080",
        "web → relay 10.0.8.2:1080",
        "cache → attacker attacker-link:18080",
    ):
        assert target in exposure, target
    assert "proxy → 1.1.1.1:443" not in exposure  # the attacker box has internet here


def test_a_binding_beyond_localhost_fails(exposed: ExposedLab) -> None:
    relay = exposed.fake.containers[3]
    relay["HostConfig"]["PortBindings"]["1080/tcp"] = [{"HostIp": "", "HostPort": "1080"}]
    exposed.host_reaches.add(("192.168.1.20", 1080))
    failed = {c.target for c in failures(exposed.run())}
    assert failed == {"relay ports", "192.168.1.20:1080"}


def test_a_target_that_reaches_the_proxy_fails(exposed: ExposedLab) -> None:
    exposed.failing = {"/dev/tcp/10.0.1.3/1080"}  # the attacker box's dmz address
    failed = failures(exposed.run())
    assert {c.target for c in failed} == {
        "web → attacker 10.0.1.3:1080",
        "cache → attacker 10.0.1.3:1080",
    }
    assert all(c.detail == "the target can use the relay" for c in failed)


def test_the_proxy_must_reach_the_services(exposed: ExposedLab) -> None:
    exposed.proxy_reaches = set()
    (failed,) = failures(exposed.run())
    assert failed.target == "proxy → web:8080"


def test_the_proxy_gives_an_optional_port_only_a_short_window(
    exposed: ExposedLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    from test_validate import with_extra_optional_web_port

    asked: list[int] = []

    def connect(proxy, host: str, port: int, timeout: float = 5.0) -> bool:
        if host == "web":
            asked.append(port)
        return (host, port) in exposed.proxy_reaches

    monkeypatch.setattr(socks, "connect", connect)
    monkeypatch.setattr(probe_module, "OPTIONAL_GRACE", 0)
    started = time.monotonic()
    checks = exposed.run(index=with_extra_optional_web_port(9999), ready_timeout=60)
    assert time.monotonic() - started < 10  # not the 60 s deadline
    assert failures(checks) == []
    (warned,) = [c for c in checks if c.target == "proxy → web:9999"]
    assert not warned.ok and warned.level == "warning"
    assert asked[0] == 8080 and 9999 in asked  # the required port first


def test_without_internet_the_proxy_must_give_none(exposed: ExposedLab, tmp_path: Path) -> None:
    source = Path(state_store.load(exposed.workspace.root)["dmz-redis"].source)
    source.write_text(source.read_text() + "  internet: false\n")
    assert failures(exposed.run()) == []
    exposed.proxy_reaches.add(("example.com", 443))
    (failed,) = failures(exposed.run())
    assert failed.target == "proxy → example.com:443"


# --- the SOCKS5 client ---------------------------------------------------------------------


class _Socks(socketserver.BaseRequestHandler):
    allowed: ClassVar[set[tuple[str, int]]] = {("web", 8080)}

    def handle(self) -> None:
        request = self.request
        assert request.recv(3) == b"\x05\x01\x00"
        request.sendall(b"\x05\x00")
        head = request.recv(5)
        name = request.recv(head[4]).decode()
        port = int.from_bytes(request.recv(2), "big")
        code = 0 if (name, port) in self.allowed else 5
        request.sendall(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))


def test_socks_client_against_a_fake_server() -> None:
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Socks) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy: Any = server.server_address
        assert socks.connect(proxy, "web", 8080)
        assert not socks.connect(proxy, "example.com", 443)
        server.shutdown()
    assert not socks.connect(("127.0.0.1", 1), "web", 8080)  # no proxy at all

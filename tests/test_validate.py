import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_runtime import DMZ_REDIS, FakeDocker, container, done

from sosya import runtime
from sosya.catalog.loader import load_index
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker
from sosya.scenario import flags
from sosya.validate import failures, validate
from sosya.validate import probes as probe_module

PROJECT = "sosya-dmz-redis"
IPS = {
    "web": {"dmz": "10.0.1.2", "internal": "10.0.2.2"},
    "cache": {"internal": "10.0.2.3"},
    "attacker": {"dmz": "10.0.1.3", "egress": "10.0.9.2"},
}
_PROBE = re.compile(r"^(reach|block) '?([an]\d+)'? ", re.MULTILINE)


def inspected(
    service: str,
    *,
    role: str = "target",
    state: str = "running",
    exit_code: int = 0,
    health: str | None = None,
) -> dict[str, Any]:
    data = container(service, role=role, state=state)
    data["State"]["ExitCode"] = exit_code
    if health:
        data["State"]["Health"] = {"Status": health}
    data["NetworkSettings"] = {
        "Networks": {f"{PROJECT}_{net}": {"IPAddress": ip} for net, ip in IPS[service].items()},
        "Ports": {},
    }
    data["HostConfig"] = {"PortBindings": {}}
    return data


class Lab:
    """A fake running dmz-redis: probes answer ok unless listed in `failing`."""

    def __init__(self, tmp_path: Path) -> None:
        self.fake = FakeDocker()
        self.fake.containers = [
            inspected("web"),
            inspected("cache"),
            inspected("attacker", role="attacker"),
        ]
        self.failing: set[str] = set()  # probe targets (checks) that must come out wrong
        self.scripts: dict[str, str] = {}
        self.values = {"web": flags.new_flag(), "cache": flags.new_flag()}
        source = tmp_path / "range.yaml"
        source.write_text(DMZ_REDIS)
        self.workspace = runtime.Workspace(tmp_path / ".sosya")
        state_store.record(
            self.workspace.root,
            state_store.RangeState(
                name="dmz-redis",
                project=PROJECT,
                compose_file=str(tmp_path / "c.yml"),
                source=str(source),
                started_at="t",
                flags={h: {"path": "/flag.txt", "value": v} for h, v in self.values.items()},
            ),
        )
        self.fake.on(lambda a: a[:1] in (["exec"], ["run"]), self.answer)
        self.fake.on(lambda a: a[:1] == ["cp"] and a[-1] == "-", self.copy_out)
        self.fake.on(lambda a: a[:1] == ["inspect"], self.inspect)

    def inspect(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        wanted = args[1:]
        found = [c for c in self.fake.containers if any(c["Id"].startswith(w) for w in wanted)]
        return done(json.dumps(found))

    def answer(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        script = args[-1]
        where = args[1] if args[0] == "exec" else args[3]
        self.scripts[where] = script
        lines = []
        for _kind, probe_id in _PROBE.findall(script):
            wrong = any(
                marker in script.split(probe_id, 1)[1].split("\n", 1)[0] for marker in self.failing
            )
            # reach succeeds and block fails when nothing is wrong
            ok = not wrong
            lines.append(f"{probe_id} {'ok' if ok else 'fail'}")
        return done("\n".join(lines))

    def copy_out(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        cid = args[1].split(":", 1)[0]
        service = next(
            c["Config"]["Labels"]["com.docker.compose.service"]
            for c in self.fake.containers
            if c["Id"].startswith(cid)
        )
        archive = flags.archive("flag.txt", (self.values[service] + "\n").encode())
        return subprocess.CompletedProcess(args, 0, archive, b"")

    def run(self, **kwargs: Any):
        return validate(
            "dmz-redis",
            workspace=self.workspace,
            docker=Docker(runner=self.fake),
            ready_timeout=5,
            **kwargs,
        )


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Lab:
    monkeypatch.setattr(probe_module, "host_connects", lambda ip, port, timeout=2.0: False)
    return Lab(tmp_path)


def by(checks, group: str) -> dict[str, Any]:
    return {c.target: c for c in checks if c.group == group}


def test_a_healthy_range_passes_every_check(lab: Lab) -> None:
    checks = lab.run()
    assert failures(checks) == []
    groups = {c.group for c in checks}
    assert groups == {
        "service",
        "reach",
        "callback",
        "segmentation",
        "no internet",
        "host isolation",
        "attacker",
        "flag",
    }
    reach = by(checks, "reach")
    assert set(reach) == {"web:8080", "web 10.0.1.2:8080"}
    segmentation = by(checks, "segmentation")
    assert "cache (dns)" in segmentation and "cache 10.0.2.3:6379 (internal)" in segmentation
    assert set(by(checks, "flag")) == {"web", "cache"}
    # cache shares no segment with the attacker box: it gets no callback check
    assert set(by(checks, "callback")) == {"web → attacker (dmz)"}


def test_one_script_per_namespace(lab: Lab) -> None:
    lab.run()
    execs = [e for e in lab.fake.commands("exec") if e[1] != "-d" and e[2] != "pkill"]
    runs = lab.fake.commands("run")
    assert len(execs) == 1  # the attacker box
    assert len(runs) == 2  # web and cache, each probed in its own namespace
    for run in runs:
        assert run[:3] == ["run", "--rm", "--network"]
        assert run[3].startswith("container:")
        assert run[6] == runtime.attacker.image()  # no alpine pull


def test_a_target_with_internet_fails(lab: Lab) -> None:
    lab.failing = {"1.1.1.1"}
    checks = lab.run()
    failed = failures(checks)
    assert {c.target for c in failed} == {"web (tcp)", "cache (tcp)"}
    assert all(c.detail == "the target reaches the internet" for c in failed)


def test_an_unreachable_service_fails_with_its_host(lab: Lab) -> None:
    lab.failing = {"/dev/tcp/web/8080"}
    (failed,) = failures(lab.run())
    assert failed.group == "reach" and failed.host == "web"


def test_attacker_internet_is_only_a_warning(lab: Lab) -> None:
    lab.failing = {"example.com && curl"}
    checks = lab.run()
    assert failures(checks) == []
    (warning,) = [c for c in checks if not c.ok]
    assert warning.level == "warning" and warning.target == "internet access"


def test_host_reaching_a_target_fails(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        probe_module, "host_connects", lambda ip, port, timeout=2.0: ip == "10.0.2.3"
    )
    (failed,) = failures(lab.run())
    assert failed.group == "host isolation" and failed.host == "cache"


def test_published_ports_fail(lab: Lab) -> None:
    lab.fake.containers[0]["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostPort": "8080"}]}
    (failed,) = failures(lab.run())
    assert failed.target == "web ports" and "8080/tcp" in failed.detail


def test_a_changed_flag_fails(lab: Lab) -> None:
    lab.values["cache"] = "SOSYA{tampered}"
    (failed,) = failures(lab.run())
    assert failed.group == "flag" and failed.target == "cache"
    assert "tampered" not in failed.detail


def test_one_shots_exited_zero_count_as_done(lab: Lab) -> None:
    lab.fake.containers[1] = inspected("cache", state="exited", exit_code=0)
    checks = lab.run()
    assert by(checks, "service")["cache"].ok
    assert by(checks, "service")["cache"].detail == "ran once, exited 0"
    lab.fake.containers[1] = inspected("cache", state="exited", exit_code=1)
    assert not by(lab.run(), "service")["cache"].ok


def test_unhealthy_services_fail(lab: Lab) -> None:
    lab.fake.containers[0] = inspected("web", health="unhealthy")
    assert not by(lab.run(), "service")["web"].ok


def test_validate_needs_a_recorded_running_range(tmp_path: Path) -> None:
    with pytest.raises(runtime.RangeError, match="no range named"):
        validate("nope", workspace=runtime.Workspace(tmp_path), docker=Docker(runner=FakeDocker()))


def test_script_shape() -> None:
    probes = [probe_module.Probe("a1", "reach", "true"), probe_module.Probe("a2", "block", "false")]
    script = probe_module.script(probes, 7)
    assert "+ 7 ))" in script and script.rstrip().endswith("wait")
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True).stdout
    assert probe_module.parse(out, probes) == {"a1": True, "a2": True}
    assert probe_module.parse("a1 ok", probes) == {"a1": True, "a2": False}


def test_index_is_the_real_one() -> None:
    assert load_index().get("vulhub/struts2/s2-045") is not None


def _with_optional_web_port(port: int) -> Any:
    index = load_index()
    entry = index.get("vulhub/struts2/s2-045")
    assert entry is not None
    services = [
        s.model_copy(
            update={
                "ports": [
                    p.model_copy(update={"optional": True, "reason": "never listens"})
                    if p.port == port
                    else p
                    for p in s.ports
                ]
            }
        )
        for s in entry.services
    ]
    changed = entry.model_copy(update={"services": services})
    entries = [changed if e.id == entry.id else e for e in index.entries]
    return index.model_copy(update={"entries": entries})


def test_a_closed_optional_port_is_only_a_warning(lab: Lab) -> None:
    lab.failing = {"/dev/tcp/web/8080", "/dev/tcp/10.0.1.2/8080"}
    checks = lab.run(index=_with_optional_web_port(8080))
    assert failures(checks) == []
    warned = [c for c in checks if not c.ok]
    assert {c.target for c in warned} == {"web:8080", "web 10.0.1.2:8080"}
    assert all(c.level == "warning" and "optional port: never listens" in c.detail for c in warned)


def test_an_open_optional_port_passes_quietly(lab: Lab) -> None:
    checks = lab.run(index=_with_optional_web_port(8080))
    assert all(c.ok for c in checks if c.target.startswith("web") and c.group == "reach")


def test_the_callback_listener_binds_only_the_shared_segment(lab: Lab) -> None:
    lab.run()
    listeners = [e for e in lab.fake.commands("exec") if e[1] == "-d"]
    (listener,) = listeners
    assert listener[2] == "attacker0000"
    (listen,) = [arg for arg in listener if arg.startswith("TCP-LISTEN:")]
    port = int(listen.split(":", 1)[1].split(",", 1)[0])
    assert 40000 <= port <= 59999
    assert f"bind={IPS['attacker']['dmz']}," in listen  # never egress or relay
    stops = [e for e in lab.fake.commands("exec") if e[2:4] == ["pkill", "-f"]]
    assert stops == [["exec", "attacker0000", "pkill", "-f", f"TCP-LISTEN:{port},"]]
    web = next(s for where, s in lab.scripts.items() if where.startswith("container:web"))
    assert f"/dev/tcp/{IPS['attacker']['dmz']}/{port}" in web


def test_a_failed_callback_fails_with_its_host(lab: Lab) -> None:
    lab.failing = {f"/dev/tcp/{IPS['attacker']['dmz']}/"}
    failed = failures(lab.run())
    assert [(c.group, c.target, c.host) for c in failed] == [
        ("callback", "web → attacker (dmz)", "web")
    ]
    assert "no connection" in failed[0].detail

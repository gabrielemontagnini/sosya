import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sosya import attacker, engine, runtime
from sosya.runtime import state as state_store
from sosya.runtime import vulhub
from sosya.runtime.docker import Docker

DMZ_REDIS = """\
apiVersion: sosya/v1
name: dmz-redis
networks: [dmz, internal]
hosts:
  - name: web
    component: vulhub/struts2/s2-045
    networks: [dmz, internal]
  - name: cache
    component: vulhub/redis/4-unacc
    networks: [internal]
attacker:
  networks: [dmz]
"""


def done(stdout: str = "", code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, stderr)


def container(
    service: str,
    *,
    role: str = "target",
    range_name: str = "dmz-redis",
    config: str = "",
    state: str = "running",
    cid: str = "",
) -> dict[str, Any]:
    labels = {
        "com.docker.compose.project": f"sosya-{range_name}",
        "com.docker.compose.service": service,
        "com.docker.compose.project.config_files": config,
        "com.docker.compose.project.working_dir": str(Path(config).parent) if config else "",
        "sosya.range": range_name,
        "sosya.host": service,
        "sosya.role": role,
    }
    return {
        "Id": cid or f"{service:0<12}"[:12] + "0" * 52,
        "Config": {"Labels": labels},
        "State": {"Status": state},
    }


class FakeDocker:
    """Records every docker argv and answers with the first matching handler."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.containers: list[dict[str, Any]] = []
        self.missing_images: set[str] = set()
        self.handlers: list[tuple[Callable[[list[str]], bool], Callable[[list[str]], Any]]] = []

    def on(self, match: Callable[[list[str]], bool], answer: Callable[[list[str]], Any]) -> None:
        self.handlers.insert(0, (match, answer))

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        args = argv[1:]
        for match, answer in self.handlers:
            if match(args):
                return answer(args)
        if args[:1] == ["ps"]:
            project = next((a.split("=", 2)[2] for a in args if a.count("=") == 2), None)
            ids = [
                c["Id"]
                for c in self.containers
                if project is None or c["Config"]["Labels"]["com.docker.compose.project"] == project
            ]
            return done("\n".join(ids))
        if args[:1] == ["inspect"]:
            wanted = set(args[1:])
            return done(json.dumps([c for c in self.containers if c["Id"] in wanted]))
        if args[:2] == ["image", "inspect"]:
            return done(code=1 if args[-1] in self.missing_images else 0)
        return done()

    def commands(self, *prefix: str) -> list[list[str]]:
        return [call[1:] for call in self.calls if call[1 : 1 + len(prefix)] == list(prefix)]


class Log:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def __call__(self, level: str, text: str) -> None:
        self.lines.append((level, text))

    def text(self) -> str:
        return "\n".join(text for _, text in self.lines)


def start(range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, **kwargs: Any):
    log = Log()
    options: dict[str, Any] = {"confirm": lambda lines: True}
    options.update(kwargs)
    record = runtime.up(
        range_dir, report=log, workspace=workspace, docker=Docker(runner=fake), **options
    )
    return record, log


def test_up_renders_records_state_first_and_starts(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    compose_file = workspace.compose_file("dmz-redis").resolve()

    def compose_up(args: list[str]) -> Any:
        # The state must exist before any container starts.
        assert "dmz-redis" in state_store.load(workspace.root)
        return done()

    fake.on(lambda a: a[:1] == ["compose"] and "up" in a, compose_up)
    record, log = start(range_dir, workspace, fake)
    assert record.project == "sosya-dmz-redis"
    assert compose_file.is_file()
    for call in fake.commands("compose"):
        assert call[1:5] == ["-p", "sosya-dmz-redis", "-f", str(compose_file)]
    verbs = [call[5] for call in fake.commands("compose")]
    assert verbs == ["config", "up"]
    assert "--wait" in fake.commands("compose")[-1]
    assert fake.commands("pull") == []  # every image is already present
    assert "sosya shell dmz-redis" in log.text()


def test_up_pulls_only_missing_images_for_their_platform(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    fake.missing_images = {"vulhub/redis:4.0.14"}
    start(range_dir, workspace, fake)
    assert fake.commands("pull") == [
        ["pull", "--quiet", "--platform", "linux/amd64", "vulhub/redis:4.0.14"]
    ]


def test_up_builds_the_attacker_when_the_pull_fails(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    image = attacker.image()
    fake.missing_images = {image}
    fake.on(lambda a: a[:1] == ["pull"] and a[-1] == image, lambda a: done(code=1, stderr="denied"))
    _, log = start(range_dir, workspace, fake)
    [build] = fake.commands("build")
    assert build[:3] == ["build", "--tag", image]
    assert Path(build[3], "Dockerfile").is_file()
    assert ("warn" in {level for level, _ in log.lines}) and "few minutes" in log.text()
    assert "python -m" not in log.text()


def test_up_refuses_a_range_running_from_another_directory(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    fake.containers = [
        container("web", config="/elsewhere/.sosya/ranges/dmz-redis/docker-compose.yml")
    ]
    with pytest.raises(runtime.RangeError, match="already running from /elsewhere"):
        start(range_dir, workspace, fake)
    assert fake.commands("compose") == []


def test_up_explains_subnet_exhaustion(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    error = "Error response from daemon: all predefined address pools have been fully subnetted"
    fake.on(lambda a: a[:1] == ["compose"] and "up" in a, lambda a: done(code=1, stderr=error))
    fake.on(
        lambda a: a[:1] == ["ps"] and not any("project=" in x for x in a),
        lambda a: done("other1"),
    )
    fake.containers = [container("web", range_name="other", cid="other1" + "0" * 58)]
    fake.containers[0]["Id"] = "other1"
    with pytest.raises(runtime.RangeError, match="no free subnets") as info:
        start(range_dir, workspace, fake)
    assert "sosya down" in str(info.value)
    assert "Running ranges: other" in str(info.value)
    # Half-started ranges stay recorded so that `down` can clean them up.
    assert "dmz-redis" in state_store.load(workspace.root)


def test_up_reports_invalid_ranges(
    tmp_path: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    (tmp_path / "range.yaml").write_text(DMZ_REDIS.replace("s2-045", "s2-999"))
    with pytest.raises(runtime.RangeError, match="not in the catalog"):
        start(tmp_path, workspace, fake)


def test_up_stops_when_the_engine_is_too_old(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine, "engine_problem", lambda: "Docker Engine 27.5.1 is too old")
    with pytest.raises(runtime.RangeError, match="too old"):
        start(range_dir, workspace, fake)
    assert fake.calls == []


def test_dangerous_range_needs_the_flag_and_a_confirmation(
    tmp_path: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    text = DMZ_REDIS.replace("vulhub/struts2/s2-045", "vulhub/docker/unauthorized-rce")
    (tmp_path / "range.yaml").write_text(text)
    with pytest.raises(runtime.RangeError, match="--allow-privileged"):
        start(tmp_path, workspace, fake)
    asked: list[list[str]] = []

    def refuse(lines: list[str]) -> bool:
        asked.append(lines)
        return False

    with pytest.raises(runtime.RangeError, match="cancelled"):
        start(tmp_path, workspace, fake, allow_privileged=True, confirm=refuse)
    assert asked == [["web (vulhub/docker/unauthorized-rce), service docker: privileged"]]
    assert fake.commands("compose") == []


def test_up_copies_bind_files_into_the_range(
    tmp_path: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "cache"
    (checkout / "samba/CVE-2017-7494").mkdir(parents=True)
    (checkout / "samba/CVE-2017-7494/smb.conf").write_text("[global]\n")
    monkeypatch.setattr(vulhub, "ensure", lambda paths: checkout)
    (tmp_path / "range.yaml").write_text(
        DMZ_REDIS.replace("vulhub/struts2/s2-045", "vulhub/samba/CVE-2017-7494")
    )
    start(tmp_path, workspace, fake)
    copy = workspace.files_dir("dmz-redis").resolve() / "web" / "smb.conf"
    assert copy.read_text() == "[global]\n"
    rendered = workspace.compose_file("dmz-redis").read_text()
    assert f"{copy}:/usr/local/samba/etc/smb.conf" in rendered


def test_down_uses_the_recorded_compose_file_and_deletes_the_files(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    start(range_dir, workspace, fake)
    compose_file = workspace.compose_file("dmz-redis").resolve()
    fake.containers = [container("web", config=str(compose_file))]
    log = Log()
    runtime.down("dmz-redis", report=log, workspace=workspace, docker=Docker(runner=fake))
    [down] = [c for c in fake.commands("compose") if "down" in c]
    assert down[1:5] == ["-p", "sosya-dmz-redis", "-f", str(compose_file)]
    assert "--volumes" in down
    assert not workspace.range_dir("dmz-redis").exists()
    assert state_store.load(workspace.root) == {}


def test_down_without_local_state_finds_the_range_by_its_labels(
    tmp_path: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    other = tmp_path / "other" / ".sosya" / "ranges" / "dmz-redis"
    other.mkdir(parents=True)
    (other / "docker-compose.yml").write_text("name: sosya-dmz-redis\n")
    fake.containers = [container("web", config=str(other / "docker-compose.yml"))]
    runtime.down("dmz-redis", report=Log(), workspace=workspace, docker=Docker(runner=fake))
    [down] = [c for c in fake.commands("compose") if "down" in c]
    assert down[4] == str(other / "docker-compose.yml")
    assert not other.exists()


def test_down_without_any_compose_file_removes_by_label(
    workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    fake.containers = [container("web", config="/gone/docker-compose.yml")]
    fake.on(lambda a: a[:2] == ["network", "ls"], lambda a: done("net1\nnet2\n"))
    runtime.down("dmz-redis", report=Log(), workspace=workspace, docker=Docker(runner=fake))
    assert fake.commands("compose") == []
    assert fake.commands("rm")[0][:3] == ["rm", "--force", "--volumes"]
    assert fake.commands("network", "rm") == [["network", "rm", "net1", "net2"]]


def test_down_of_an_unknown_range_fails(workspace: runtime.Workspace, fake: FakeDocker) -> None:
    with pytest.raises(runtime.RangeError, match="no range named lab"):
        runtime.down("lab", report=Log(), workspace=workspace, docker=Docker(runner=fake))


def test_down_removes_root_owned_files_with_a_container(
    tmp_path: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / ".sosya" / "ranges" / "lab"
    target.mkdir(parents=True)
    calls = {"n": 0}
    real_rmtree = runtime.shutil.rmtree

    def rmtree(path: Path, ignore_errors: bool = False) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError("root-owned file")
        real_rmtree(path, ignore_errors=ignore_errors)

    monkeypatch.setattr(runtime.shutil, "rmtree", rmtree)
    runtime._remove_tree(target, Docker(runner=fake))
    [run] = fake.commands("run")
    assert run[:4] == ["run", "--rm", "--network", "none"]
    assert run[-3:] == ["rm", "-rf", "/cleanup/lab"]
    assert not target.exists()


def test_status_lists_local_and_foreign_ranges(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    start(range_dir, workspace, fake)
    fake.containers = [
        container("web", config=str(workspace.compose_file("dmz-redis").resolve())),
        container("attacker", role="attacker", config="x"),
        container("db", range_name="far", config="/far/.sosya/ranges/far/docker-compose.yml"),
    ]
    found = {r.name: r for r in runtime.status(workspace=workspace, docker=Docker(runner=fake))}
    assert set(found) == {"dmz-redis", "far"}
    assert found["dmz-redis"].local and found["dmz-redis"].running
    assert [s.service for s in found["dmz-redis"].services] == ["attacker", "web"]
    assert not found["far"].local
    assert found["far"].location == "/far/.sosya/ranges/far"


def test_shell_execs_into_the_attacker_box(workspace: runtime.Workspace, fake: FakeDocker) -> None:
    fake.containers = [container("web"), container("attacker", role="attacker", cid="a" * 64)]
    assert runtime.shell("dmz-redis", docker=Docker(runner=fake)) == 0
    [call] = fake.commands("exec")
    assert call[-2:] == ["a" * 12, "bash"]


def test_shell_without_a_running_attacker(workspace: runtime.Workspace, fake: FakeDocker) -> None:
    with pytest.raises(runtime.RangeError, match="no range named dmz-redis is running"):
        runtime.shell("dmz-redis", docker=Docker(runner=fake))
    fake.containers = [container("attacker", role="attacker", state="exited")]
    with pytest.raises(runtime.RangeError, match="not running"):
        runtime.shell("dmz-redis", docker=Docker(runner=fake))


def test_only_running_range(fake: FakeDocker) -> None:
    docker = Docker(runner=fake)
    with pytest.raises(runtime.RangeError, match="no range is running"):
        runtime.only_running_range(docker=docker)
    fake.containers = [
        container("web"),
        container("attacker", role="attacker"),
        container("attacker", role="attacker", range_name="old", state="exited"),
    ]
    assert runtime.only_running_range(docker=docker) == "dmz-redis"
    fake.containers.append(container("attacker", role="attacker", range_name="solr"))
    with pytest.raises(runtime.RangeError, match=r"2 ranges are running \(dmz-redis, solr\)"):
        runtime.only_running_range(docker=docker)


def test_state_round_trip_and_damaged_file(tmp_path: Path) -> None:
    record = state_store.RangeState(
        "lab", "sosya-lab", "/x/docker-compose.yml", "/x/range.yaml", "t"
    )
    state_store.record(tmp_path, record)
    assert state_store.load(tmp_path) == {"lab": record}
    state_store.forget(tmp_path, "lab")
    assert state_store.load(tmp_path) == {}
    (tmp_path / "state.json").write_text("{not json")
    assert state_store.load(tmp_path) == {}


def test_vulhub_download_is_sparse_and_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sosya.catalog import VULHUB_COMMIT
    from sosya.catalog import git as gitmod

    calls: list[list[str]] = []
    checkout = tmp_path / "vulhub"

    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd[3:])
        if cmd[3:5] == ["checkout", "--quiet"]:
            (checkout / "samba/CVE-2017-7494").mkdir(parents=True)
        if cmd[3] == "rev-parse":
            done_checkout = (checkout / "samba").exists()
            return subprocess.CompletedProcess(cmd, 0 if done_checkout else 1, VULHUB_COMMIT, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(gitmod.subprocess, "run", run)
    assert vulhub.ensure(["samba/CVE-2017-7494"], checkout) == checkout
    sparse = next(c for c in calls if c[:2] == ["sparse-checkout", "set"])
    assert sparse == ["sparse-checkout", "set", "--no-cone", "/samba/CVE-2017-7494/"]
    fetch = next(c for c in calls if c[0] == "fetch")
    assert fetch[-1] == VULHUB_COMMIT and "--filter=blob:none" in fetch


# --- one-shot services ----------------------------------------------------------------------


def one_shot(service: str, state: str, exit_code: int = 0, health: str | None = None) -> dict:
    data = container(service, state=state)
    data["State"]["ExitCode"] = exit_code
    if health:
        data["State"]["Health"] = {"Status": health}
    return data


def test_a_one_shot_that_exited_zero_does_not_fail_up(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime.time, "sleep", lambda s: None)
    fake.containers = [one_shot("web", "running"), one_shot("cache", "exited", 0)]
    error = "container sosya-dmz-redis-cache-1 exited (0)"
    fake.on(lambda a: a[:1] == ["compose"] and "up" in a, lambda a: done(code=1, stderr=error))
    _, log = start(range_dir, workspace, fake)
    assert ("ok", "cache ran once and completed") in log.lines


def test_waits_for_the_others_after_a_one_shot(fake: FakeDocker) -> None:
    states = iter(["starting", "starting", "healthy"])
    sleeps: list[float] = []

    def ps_then_inspect(args: list[str]) -> Any:
        fake.containers = [
            one_shot("web", "running", health=next(states)),
            one_shot("init", "exited"),
        ]
        return done("\n".join(c["Id"] for c in fake.containers))

    fake.on(lambda a: a[:1] == ["ps"], ps_then_inspect)
    assert runtime._wait_past_one_shots(
        Docker(runner=fake), "sosya-dmz-redis", 1e12, sleep=sleeps.append
    )
    assert len(sleeps) == 2


@pytest.mark.parametrize(
    "containers",
    [
        [one_shot("web", "running"), one_shot("init", "exited", 1)],
        [one_shot("web", "running", health="unhealthy"), one_shot("init", "exited")],
        [one_shot("web", "exited", 2)],
        [one_shot("web", "running", health="starting")],  # no one-shot: a real failure
    ],
)
def test_real_failures_still_fail(fake: FakeDocker, containers: list[dict]) -> None:
    fake.containers = containers
    assert not runtime._wait_past_one_shots(
        Docker(runner=fake), "sosya-dmz-redis", 0, sleep=lambda s: None
    )


def test_the_wait_ends_at_the_deadline(fake: FakeDocker) -> None:
    fake.containers = [one_shot("web", "running", health="starting"), one_shot("init", "exited")]
    clock = iter([0.0, 5.0, 11.0])
    assert not runtime._wait_past_one_shots(
        Docker(runner=fake),
        "sosya-dmz-redis",
        10.0,
        sleep=lambda s: None,
        clock=lambda: next(clock),
    )

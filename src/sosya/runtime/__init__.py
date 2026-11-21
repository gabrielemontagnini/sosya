"""Start, stop, list and enter ranges with `docker compose`. No LLM, no Docker SDK."""

import shutil
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from sosya import attacker, engine
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import Entry
from sosya.render import PROJECT_PREFIX, RenderError, dump, project_name, render
from sosya.runtime import state as state_store
from sosya.runtime import vulhub
from sosya.runtime.docker import ContainerInfo, Docker, DockerError
from sosya.scenario import flags as flag_store
from sosya.scenario import markdown as scenario
from sosya.spec import RangeSpec, SpecError, check_catalog, errors, load_range, range_file

WORKSPACE = Path(".sosya")
ATTEMPTS = "attempts"
WAIT_TIMEOUT = 600
SUBNET_EXHAUSTED = (
    "all predefined address pools have been fully subnetted",
    "could not find an available, non-overlapping ipv4 address pool",
)

Level = Literal["ok", "warn", "fail", "info"]


class Reporter(Protocol):
    def __call__(self, level: Level, text: str) -> None: ...


class RangeError(RuntimeError):
    """A range that cannot be started, stopped or entered. The message is for the user."""


class HostEnvironmentError(RangeError):
    """A failure of the machine, not of the range: changing a component would not fix it.

    Docker Hub's pull limit, no network, a full disk, no free subnets, an unreachable or too
    old Docker daemon. The repair loop stops on these instead of spending attempts.
    """


ENVIRONMENT_MARKERS = (
    "toomanyrequests",
    "too many requests",
    "rate limit",
    "no space left on device",
    "temporary failure in name resolution",
    "network is unreachable",
    "i/o timeout",
    "tls handshake timeout",
    "connection reset by peer",
    "could not resolve host",
    "cannot connect to the docker daemon",
    "dial tcp",
)
COMPONENT_MARKERS = (
    "manifest unknown",
    "pull access denied",
    "repository does not exist",
    "no matching manifest",
    "not found",
)


def classify(message: str) -> type[RangeError]:
    """`HostEnvironmentError` for problems of the machine, `RangeError` for the range's own."""
    lowered = message.lower()
    if any(marker in lowered for marker in COMPONENT_MARKERS):
        return RangeError  # the image or tag is wrong: another component may work
    if any(marker in lowered for marker in (*ENVIRONMENT_MARKERS, *SUBNET_EXHAUSTED)):
        return HostEnvironmentError
    return RangeError


@dataclass(frozen=True)
class Workspace:
    root: Path = WORKSPACE

    def range_dir(self, name: str) -> Path:
        return self.root / "ranges" / name

    def compose_file(self, name: str) -> Path:
        return self.range_dir(name) / "docker-compose.yml"

    def files_dir(self, name: str) -> Path:
        return self.range_dir(name) / "files"

    def scenario_file(self, name: str) -> Path:
        return self.range_dir(name) / "SCENARIO.md"

    def attempts_dir(self, name: str) -> Path:
        return self.range_dir(name) / ATTEMPTS


@dataclass(frozen=True)
class ServiceStatus:
    service: str
    host: str
    role: str
    state: str
    health: str | None


@dataclass(frozen=True)
class RangeStatus:
    name: str
    project: str
    location: str
    local: bool
    services: list[ServiceStatus] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return any(s.state == "running" for s in self.services)


def _tail(text: str, lines: int = 8) -> str:
    kept = [line for line in text.strip().splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


# --- up --------------------------------------------------------------------------------------


def _dangerous_lines(spec: RangeSpec, entries: dict[str, Entry]) -> list[str]:
    lines = []
    for host in spec.hosts:
        entry = entries[host.name]
        for reason in entry.dangerous:
            lines.append(f"{host.name} ({entry.id}), service {reason.service}: {reason.reason}")
    return lines


def _ensure_attacker(docker: Docker, report: Reporter) -> str:
    image = attacker.image()
    if docker.image_exists(image):
        report("ok", f"attacker box image {image}")
        return image
    report("info", f"pulling the attacker box image {image}")
    pulled = docker.pull(image)
    if pulled.returncode == 0:
        report("ok", f"attacker box image {image}")
        return image
    report(
        "warn",
        "the attacker box image could not be pulled; building it from the Dockerfile shipped "
        "with Sosya. This takes a few minutes.",
    )
    with attacker.build_context() as context:
        built = docker.build(image, context)
    if built.returncode != 0:
        raise RangeError(f"could not build the attacker box image:\n{_tail(built.stderr)}")
    report("ok", f"attacker box image {image} built")
    return image


def _copy_files(spec: RangeSpec, entries: dict[str, Entry], checkout: Path, files: Path) -> None:
    """Give each host that bind-mounts files its own copy: targets get compromised."""
    for host in spec.hosts:
        entry = entries[host.name]
        if not any(f.kind == "bind" for f in entry.local_files):
            continue
        destination = files / host.name
        if destination.exists():
            continue  # a range that is already running keeps its (possibly modified) files
        shutil.copytree(checkout / entry.path, destination, ignore=shutil.ignore_patterns(".git"))


def _pull_missing(docker: Docker, compose: dict, report: Reporter) -> None:
    """Pull only images that are not present: tags are pinned, and pulls cost rate limit."""
    seen: set[str] = set()
    for name, service in compose["services"].items():
        image = service.get("image")
        if not image or "build" in service or image in seen or name == "attacker":
            continue
        seen.add(image)
        if docker.image_exists(image):
            report("ok", f"image {image} present")
            continue
        report("info", f"pulling {image}")
        proc = docker.pull(image, service.get("platform"))
        if proc.returncode != 0:
            raise classify(proc.stderr)(f"could not pull {image}:\n{_tail(proc.stderr)}")
        report("ok", f"image {image} pulled")


def _up_failure(stderr: str, docker: Docker, name: str) -> RangeError:
    lowered = stderr.lower()
    if any(marker in lowered for marker in SUBNET_EXHAUSTED):
        others = sorted({c.range for c in docker.containers() if c.range and c.range != name})
        hint = f" Running ranges: {', '.join(others)}." if others else ""
        return HostEnvironmentError(
            "Docker has no free subnets left for the range's networks. Stop ranges you no "
            f"longer need with `sosya down <name>`.{hint}"
        )
    return classify(stderr)(f"docker compose up failed:\n{_tail(stderr)}")


def _completed(container: ContainerInfo) -> bool:
    """A one-shot service (such as `airflow-init`) that finished its job."""
    return container.state == "exited" and container.exit_code == 0


def _ready(container: ContainerInfo) -> bool:
    return container.state == "running" and container.health in (None, "healthy")


def _wait_past_one_shots(
    docker: Docker,
    project: str,
    deadline: float,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """After a failed `up --wait`: True if it failed only because one-shot services exited 0.

    The other services may still be starting, so keep polling them until the same deadline.
    """
    while True:
        found = docker.containers(project)
        if not found:
            return False
        broken = [
            c
            for c in found
            if (c.state == "exited" and c.exit_code != 0)
            or c.health == "unhealthy"
            or c.state in ("dead", "restarting")
        ]
        if broken or not any(_completed(c) for c in found):
            return False
        if all(_completed(c) or _ready(c) for c in found):
            return True
        if clock() >= deadline:
            return False
        sleep(2)


def up(
    path: Path,
    *,
    report: Reporter,
    confirm: Callable[[list[str]], bool],
    allow_privileged: bool = False,
    workspace: Workspace | None = None,
    docker: Docker | None = None,
) -> state_store.RangeState:
    """Start the range in `path` (a range.yaml or its directory). Return its state record."""
    workspace = workspace or Workspace()
    docker = docker or Docker()
    try:
        spec = load_range(path)
    except SpecError as exc:
        raise RangeError(str(exc)) from None
    report("ok", f"range {spec.name} from {range_file(path)}")

    problem = engine.engine_problem()
    if problem is not None:
        raise HostEnvironmentError(problem)
    platform = engine.docker_platform()
    index = load_index()
    issues = check_catalog(spec, index, host_platform=platform, allow_privileged=allow_privileged)
    for issue in issues:
        if issue.level == "warning":
            report("warn", str(issue))
    refused = errors(issues)
    if refused:
        raise RangeError("the range is not valid:\n  " + "\n  ".join(str(i) for i in refused))
    report("ok", f"checked against the catalog ({len(spec.hosts)} hosts, engine {platform})")

    entries = {host.name: index.get(host.component) for host in spec.hosts}
    resolved = {name: entry for name, entry in entries.items() if entry is not None}
    dangerous = _dangerous_lines(spec, resolved)
    if dangerous and not confirm(dangerous):
        raise RangeError("cancelled: the range was not started")

    project = project_name(spec.name)
    compose_file = workspace.compose_file(spec.name).resolve()
    others = [
        c
        for c in docker.containers(project)
        if c.config_files and c.config_files != str(compose_file)
    ]
    if others:
        where = others[0].working_dir or others[0].config_files
        raise RangeError(
            f"range {spec.name} is already running from {where}. "
            f"Stop it first with `sosya down {spec.name}`."
        )

    needs_files = [entry for entry in resolved.values() if not entry.image_only]
    checkout: Path | None = None
    if needs_files:
        try:
            checkout = vulhub.ensure(sorted({entry.path for entry in needs_files}))
        except Exception as exc:  # git missing, network down, ...
            raise HostEnvironmentError(f"could not download the Vulhub files: {exc}") from None
        report("ok", f"Vulhub files for {', '.join(sorted(e.id for e in needs_files))}")
        _copy_files(spec, resolved, checkout, workspace.files_dir(spec.name).resolve())

    image = _ensure_attacker(docker, report)
    source_root = checkout
    try:
        compose = render(
            spec,
            index,
            services_of=load_services,
            attacker_image=image,
            engine_platform=platform,
            allow_privileged=allow_privileged,
            source_dir=(lambda entry: source_root / entry.path) if source_root else None,
            files_dir=workspace.files_dir(spec.name).resolve(),
        )
    except RenderError as exc:
        raise RangeError(f"cannot render the range: {exc}") from None
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text(dump(compose), encoding="utf-8")
    report("ok", f"rendered {compose_file}")

    record = state_store.RangeState(
        name=spec.name,
        project=project,
        compose_file=str(compose_file),
        source=str(range_file(path).resolve()),
        started_at=_now(),
    )
    # Recorded before anything starts, so a range that fails half-way can still be stopped.
    state_store.record(workspace.root, record)

    checked = docker.compose(project, compose_file, "config", "--quiet")
    if checked.returncode != 0:
        raise RangeError(f"docker compose rejected the rendered file:\n{_tail(checked.stderr)}")
    _pull_missing(docker, compose, report)
    report("info", "starting containers")
    deadline = time.monotonic() + WAIT_TIMEOUT
    started = docker.compose(
        project, compose_file, "up", "--detach", "--wait", "--wait-timeout", str(WAIT_TIMEOUT)
    )
    if started.returncode != 0 and not _wait_past_one_shots(docker, project, deadline):
        raise _up_failure(started.stderr, docker, spec.name)
    for done_once in [c for c in docker.containers(project) if _completed(c)]:
        report("ok", f"{done_once.service} ran once and completed")
    report("ok", f"range {spec.name} is up")

    record = _place_flags(spec, record, docker, report)
    state_store.record(workspace.root, record)
    scenario_file = workspace.scenario_file(spec.name)
    paths = {host: flag["path"] for host, flag in record.flags.items()}
    scenario_file.write_text(scenario.render(spec, index, paths), encoding="utf-8")
    report(
        "ok",
        f"ready: open the attacker box with `sosya shell {spec.name}`; "
        f"scenario in {scenario_file.resolve()}",
    )
    return record


def _place_flags(
    spec: RangeSpec, record: state_store.RangeState, docker: Docker, report: Reporter
) -> state_store.RangeState:
    """A new random flag on every host, in its primary container. Never print the values."""
    by_key = {c.service: c for c in docker.containers(record.project) if c.role == "target"}
    placed: dict[str, dict[str, str]] = {}
    failed: list[str] = []
    for host in spec.hosts:
        container = by_key.get(host.name)  # the primary container takes the host's name
        flag = flag_store.place(docker, container.id, host.flag) if container else None
        if flag is None:
            failed.append(host.name)
            continue
        placed[host.name] = {"path": flag.path, "value": flag.value}
        if host.flag and flag.path != host.flag:
            report("warn", f"{host.name}: cannot write {host.flag}; the flag is in {flag.path}")
    if failed:
        report("warn", f"no flag could be placed on {', '.join(failed)}")
    if placed:
        where = ", ".join(f"{host} {flag['path']}" for host, flag in placed.items())
        report("ok", f"flags placed: {where}")
    return state_store.RangeState(**{**record.__dict__, "flags": placed})


# --- down ------------------------------------------------------------------------------------


def _remove_tree(path: Path, docker: Docker) -> None:
    """Delete a range's files, even those a target created as root inside a bind mount."""
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass
    docker.run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            f"{path.parent.resolve()}:/cleanup",
            attacker.image(),
            "rm",
            "-rf",
            f"/cleanup/{path.name}",
        ]
    )
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        raise RangeError(f"could not delete {path}: remove it by hand")


def _remove_range_dir(range_dir: Path, docker: Docker) -> None:
    """Delete a range's working files, but keep `attempts/`: the debug record of `sosya new`."""
    if not range_dir.exists():
        return
    keep = range_dir / ATTEMPTS
    if not keep.exists():
        _remove_tree(range_dir, docker)
        return
    for child in sorted(range_dir.iterdir()):
        if child == keep:
            continue
        if child.is_dir() and not child.is_symlink():
            _remove_tree(child, docker)
        else:
            child.unlink(missing_ok=True)


def _compose_file_of(
    record: state_store.RangeState | None, found: list[ContainerInfo]
) -> Path | None:
    candidates = [record.compose_file] if record else []
    candidates += [c.config_files for c in found if c.config_files and "," not in c.config_files]
    for candidate in candidates:
        if Path(candidate).is_file():
            return Path(candidate)
    return None


def down(
    name: str,
    *,
    report: Reporter,
    workspace: Workspace | None = None,
    docker: Docker | None = None,
) -> None:
    """Stop a range and remove its containers, networks, volumes and files."""
    workspace = workspace or Workspace()
    docker = docker or Docker()
    project = project_name(name)
    record = state_store.load(workspace.root).get(name)
    found = docker.containers(project)
    if record is None and not found:
        raise RangeError(f"no range named {name} is running")
    compose_file = _compose_file_of(record, found)
    if compose_file is not None:
        proc = docker.compose(
            project, compose_file, "down", "--volumes", "--remove-orphans", "--timeout", "5"
        )
        if proc.returncode != 0:
            raise RangeError(f"docker compose down failed:\n{_tail(proc.stderr)}")
    else:
        # No compose file left anywhere: remove what the labels point to.
        if found:
            docker.run(["rm", "--force", "--volumes", *[c.id for c in found]])
        networks = docker.project_networks(project)
        if networks:
            docker.run(["network", "rm", *networks])
    report("ok", f"containers and networks of {name} removed")
    range_dir = compose_file.parent if compose_file is not None else None
    if range_dir is not None and range_dir.parent.name == "ranges":
        _remove_range_dir(range_dir, docker)
        report("ok", f"files of {name} deleted")
    state_store.forget(workspace.root, name)


# --- status ----------------------------------------------------------------------------------


def status(
    *, workspace: Workspace | None = None, docker: Docker | None = None
) -> list[RangeStatus]:
    """Every range: those recorded here and those Docker knows about from any directory."""
    workspace = workspace or Workspace()
    docker = docker or Docker()
    records = state_store.load(workspace.root)
    by_project: dict[str, list[ContainerInfo]] = {}
    for container in docker.containers():
        if container.project.startswith(PROJECT_PREFIX):
            by_project.setdefault(container.project, []).append(container)
    ranges: list[RangeStatus] = []
    names = sorted({*records, *(c[0].range for c in by_project.values())})
    for name in names:
        project = project_name(name)
        containers = by_project.get(project, [])
        record = records.get(name)
        location = (
            str(Path(record.compose_file).parent)
            if record
            else (containers[0].working_dir if containers else "")
        )
        ranges.append(
            RangeStatus(
                name=name,
                project=project,
                location=location,
                local=record is not None,
                services=[
                    ServiceStatus(c.service, c.host, c.role, c.state, c.health)
                    for c in sorted(containers, key=lambda c: (c.role != "attacker", c.service))
                ],
            )
        )
    return ranges


# --- shell -----------------------------------------------------------------------------------


def shell(name: str, *, docker: Docker | None = None) -> int:
    """Open an interactive shell in the range's attacker box; return the shell's exit code."""
    docker = docker or Docker()
    found = docker.containers(project_name(name))
    boxes = [c for c in found if c.role == "attacker" and c.state == "running"]
    if not boxes:
        if not found:
            raise RangeError(f"no range named {name} is running: start it with `sosya up`")
        raise RangeError(f"the attacker box of {name} is not running: run `sosya up` again")
    flags = ["-it"] if sys.stdin.isatty() else ["-i"]
    return docker.run(["exec", *flags, boxes[0].id, "bash"], capture=False).returncode


__all__ = [
    "DockerError",
    "HostEnvironmentError",
    "Level",
    "RangeError",
    "RangeStatus",
    "ServiceStatus",
    "Workspace",
    "down",
    "shell",
    "state_store",
    "status",
    "up",
]

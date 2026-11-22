"""`sosya new` without the terminal: plan, check, start, validate and repair a range.

At most 3 attempts in all, static and live failures together. Each failed attempt is stopped
before the next one and kept in `.sosya/ranges/<name>/attempts/<n>/` for debugging. What goes
back to the LLM: the static issues and, for live failures, the failed checks with the last log
lines of the services involved. Warnings never do.

Failures of the machine (Docker Hub's pull limit, no network, a full disk) stop the build at
once: another component would not fix them, and they would burn the attempts.
"""

import contextlib
import json
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from sosya import engine, runtime
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex
from sosya.llm.base import LLM, LLMError, RefusalError
from sosya.planner import Candidate, Conversation, Draft, Planner
from sosya.render import project_name
from sosya.runtime import HostEnvironmentError, RangeError, Reporter, Workspace
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker
from sosya.spec import RANGE_FILE, Issue, RangeSpec, SpecError, check_catalog, load_range
from sosya.text import plural
from sosya.validate import Check, failures, validate

MAX_ATTEMPTS = 3
LOG_LINES = 30
RANGES = Path("ranges")
NAME_LIMIT = 40

DANGEROUS_MESSAGE = (
    "the plan needs environments with host-level privileges: run again "
    "with --allow-privileged to start it after a confirmation"
)

Outcome = Literal["green", "failed", "refused", "environment", "dangerous", "cancelled"]


@dataclass(frozen=True)
class Attempt:
    number: int
    result: Literal["static", "live", "environment", "green"]
    problems: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)


@dataclass
class BuildResult:
    outcome: Outcome
    message: str = ""
    name: str = ""
    spec: RangeSpec | None = None
    attempts: list[Attempt] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    phases: dict[str, float] = field(default_factory=dict)
    candidates: list[Candidate] = field(default_factory=list)
    dangerous: list[str] = field(default_factory=list)
    range_file: Path | None = None
    scenario_file: Path | None = None
    renamed_from: str = ""

    @property
    def total(self) -> float:
        return self.phases.get("total", 0.0)


def unique_name(name: str, *, workspace: Workspace, docker: Docker, ranges: Path = RANGES) -> str:
    """`name`, or `name-2`, `name-3`, ... when a range of that name exists here or runs."""
    recorded = state_store.load(workspace.root)

    def taken(candidate: str) -> bool:
        return (
            (ranges / candidate).exists()
            or candidate in recorded
            or bool(docker.containers(project_name(candidate)))
        )

    if not taken(name):
        return name
    for number in range(2, 100):
        suffix = f"-{number}"
        candidate = name[: NAME_LIMIT - len(suffix)].rstrip("-") + suffix
        if not taken(candidate):
            return candidate
    raise RangeError(f"too many ranges named {name}: remove some under {ranges}/")


class _Clock:
    def __init__(self) -> None:
        self.phases: dict[str, float] = {}

    def add(self, phase: str, seconds: float) -> None:
        self.phases[phase] = self.phases.get(phase, 0.0) + seconds


def _logs(docker: Docker, spec: RangeSpec, workspace: Workspace, checks: list[Check]) -> str:
    """The last log lines of every container of the hosts whose checks failed."""
    hosts = sorted({check.host for check in checks if check.host})
    compose_file = workspace.compose_file(spec.name).resolve()
    if not hosts or not compose_file.is_file():
        return ""
    project = project_name(spec.name)
    services = sorted(c.service for c in docker.containers(project) if c.host in hosts)
    blocks = []
    for service in services:
        proc = docker.compose(
            project, compose_file, "logs", "--no-color", "--tail", str(LOG_LINES), service
        )
        text = (proc.stdout or proc.stderr or "").strip()
        if text:
            lines = text.splitlines()[-LOG_LINES:]
            blocks.append(f"--- last log lines of {service} ---\n" + "\n".join(lines))
    return "\n".join(blocks)


def _save_attempt(
    workspace: Workspace,
    name: str,
    number: int,
    *,
    draft: Draft | None,
    spec: RangeSpec | None,
    problems: dict[str, list[str]],
    logs: str = "",
) -> Path:
    folder = workspace.attempts_dir(name) / str(number)
    folder.mkdir(parents=True, exist_ok=True)
    if spec is not None:
        (folder / RANGE_FILE).write_text(spec.to_yaml(), encoding="utf-8")
    elif draft is not None and draft.data is not None:
        (folder / "draft.json").write_text(json.dumps(draft.data, indent=2), encoding="utf-8")
    (folder / "issues.json").write_text(json.dumps(problems, indent=2) + "\n", encoding="utf-8")
    if logs:
        (folder / "logs.txt").write_text(logs + "\n", encoding="utf-8")
    compose_file = workspace.compose_file(name)
    if compose_file.is_file():
        shutil.copy2(compose_file, folder / "docker-compose.yml")
    return folder


def _is_dangerous(issue: Issue) -> bool:
    return issue.level == "warning" and "host-level" in issue.message


@dataclass(frozen=True)
class EditCheck:
    spec: RangeSpec | None
    errors: list[str]
    warnings: list[str]


def check_edited(
    path: Path,
    *,
    index: CatalogIndex | None = None,
    host_platform: str | None = None,
    services_of: Callable[[str], dict] = load_services,
) -> EditCheck:
    """Check a range the user edited by hand: the same checks as `sosya up`, any catalog id.

    Dangerous components are warnings here: the build decides about them (`--allow-privileged`
    and a confirmation), exactly as for a draft of the LLM.
    """
    try:
        spec = load_range(path)
    except SpecError as exc:
        return EditCheck(None, [str(exc)], [])
    issues = check_catalog(
        spec,
        index or load_index(),
        host_platform=host_platform,
        allow_privileged=True,
        services_of=services_of,
    )
    errors = [str(issue) for issue in issues if issue.level == "error"]
    warnings = [str(issue) for issue in issues if issue.level == "warning"]
    return EditCheck(None if errors else spec, errors, warnings)


def _check_line(check: Check) -> str:
    return f"live check failed: {check.group} {check.target}: {check.detail}"


def _quiet(report: Reporter) -> Reporter:
    """Forward only warnings and failures: `new` prints one line per phase."""

    def forward(level: runtime.Level, text: str) -> None:
        if level in ("warn", "fail"):
            report(level, text)

    return forward


def build(
    sentence: str,
    llm: LLM,
    *,
    report: Reporter,
    phase: Callable[[str, str], None],
    confirm_plan: Callable[[RangeSpec, BuildResult], bool | RangeSpec] = (
        lambda spec, result: True
    ),
    confirm_privileged: Callable[[list[str]], bool] = lambda lines: False,
    allow_privileged: bool = False,
    effort: str | None = None,
    workspace: Workspace | None = None,
    docker: Docker | None = None,
    index: CatalogIndex | None = None,
    host_platform: str | None = None,
    ranges: Path = RANGES,
    max_attempts: int = MAX_ATTEMPTS,
    up: Callable[..., state_store.RangeState] = runtime.up,
    down: Callable[..., None] = runtime.down,
    check: Callable[..., list[Check]] = validate,
) -> BuildResult:
    workspace = workspace or Workspace()
    docker = docker or Docker()
    index = index or load_index()
    clock = _Clock()
    started = time.monotonic()
    result = BuildResult(outcome="failed", phases=clock.phases)

    def finish(outcome: Outcome, message: str = "") -> BuildResult:
        result.outcome = outcome
        result.message = message
        clock.phases["total"] = time.monotonic() - started
        return result

    if host_platform is None:
        host_platform = engine.docker_platform()
    planner = Planner(
        llm,
        index,
        host_platform=host_platform,
        effort=effort,
        services_of=load_services,
        warn=lambda text: report("warn", text),
    )
    try:
        t = time.monotonic()
        queries = planner.derive_queries(sentence)
        clock.add("queries", time.monotonic() - t)
        phase("queries", ", ".join(queries) if queries else "none: searching the sentence")

        t = time.monotonic()
        found = planner.candidates(sentence, queries)
        clock.add("candidates", time.monotonic() - t)
        result.candidates = found
        emulated = sum(1 for c in found if c.emulated)
        phase("candidates", f"{len(found)}" + (f" ({emulated} emulated)" if emulated else ""))
        if not found:
            return finish("failed", "no catalog environment matches the description")

        conversation = planner.start(sentence, found)
        problems: list[str] = []
        confirmed = False
        for number in range(1, max_attempts + 1):
            t = time.monotonic()
            draft = (
                planner.repair(conversation, problems) if problems else planner.draft(conversation)
            )
            clock.add("plan", time.monotonic() - t)
            spec = draft.spec
            if conversation.name and not result.name:
                # The first draft that has a name fixes it, even if it fails other checks.
                wanted = conversation.name
                name = unique_name(wanted, workspace=workspace, docker=docker, ranges=ranges)
                if name != wanted:
                    result.renamed_from = wanted
                    report("warn", f"a range named {wanted} exists: this one is {name}")
                conversation.name = name
                result.name = name
            if spec is not None:
                spec = spec.model_copy(update={"name": result.name})
            result.spec = spec
            name = result.name or "unnamed"

            if draft.errors or spec is None:
                problems = [str(issue) for issue in draft.errors]
                phase("plan", f"attempt {number}: {plural(len(problems), 'problem')} found")
                _save_attempt(
                    workspace, name, number, draft=draft, spec=spec, problems={"static": problems}
                )
                result.attempts.append(Attempt(number, "static", problems))
                continue
            components = [host.component for host in spec.hosts]
            phase(
                "plan",
                f"attempt {number}: "
                + ", ".join(
                    f"{host.name}={host.component.removeprefix('vulhub/')}" for host in spec.hosts
                ),
            )

            dangerous = [str(issue) for issue in draft.dangerous]
            if dangerous:
                result.dangerous = dangerous
                if not allow_privileged:
                    return finish("dangerous", DANGEROUS_MESSAGE)
            if not confirmed:
                answer = confirm_plan(spec, result)
                if not answer:
                    return finish("cancelled", "cancelled: nothing was started")
                if isinstance(answer, RangeSpec):
                    spec = _adopt(answer, result, conversation, report, workspace, docker, ranges)
                    name = result.name
                    components = [host.component for host in spec.hosts]
                    issues = check_catalog(
                        spec,
                        index,
                        host_platform=host_platform,
                        allow_privileged=True,
                        services_of=load_services,
                    )
                    dangerous = [str(issue) for issue in issues if _is_dangerous(issue)]
                    result.dangerous = dangerous
                    if dangerous and not allow_privileged:
                        return finish("dangerous", DANGEROUS_MESSAGE)
                if dangerous and not confirm_privileged(dangerous):
                    return finish("cancelled", "cancelled: nothing was started")
                confirmed = True

            folder = workspace.attempts_dir(name) / str(number)
            folder.mkdir(parents=True, exist_ok=True)
            source = folder / RANGE_FILE
            source.write_text(spec.to_yaml(), encoding="utf-8")
            t = time.monotonic()
            try:
                up(
                    source,
                    report=_quiet(report),
                    confirm=lambda lines: True,
                    allow_privileged=allow_privileged,
                    workspace=workspace,
                    docker=docker,
                )
            except HostEnvironmentError as exc:
                clock.add("up", time.monotonic() - t)
                _save_attempt(
                    workspace,
                    name,
                    number,
                    draft=draft,
                    spec=spec,
                    problems={"environment": [str(exc)]},
                )
                _stop(down, name, workspace, docker)
                result.attempts.append(Attempt(number, "environment", [str(exc)], components))
                return finish("environment", str(exc))
            except RangeError as exc:
                clock.add("up", time.monotonic() - t)
                problems = [f"the range did not start: {exc}"]
                phase("up", f"attempt {number}: failed to start")
                _save_attempt(
                    workspace, name, number, draft=draft, spec=spec, problems={"live": problems}
                )
                _stop(down, name, workspace, docker)
                result.attempts.append(Attempt(number, "live", problems, components))
                continue
            clock.add("up", time.monotonic() - t)
            phase("up", f"{plural(len(spec.hosts), 'host')} running")

            t = time.monotonic()
            checks = check(name, workspace=workspace, docker=docker)
            clock.add("validate", time.monotonic() - t)
            result.checks = checks
            failed = failures(checks)
            counted = [c for c in checks if c.level == "check"]
            phase("validate", f"{len(counted) - len(failed)}/{len(counted)} checks passed")
            if not failed:
                result.attempts.append(Attempt(number, "green", [], components))
                _publish(result, spec, workspace, ranges)
                return finish("green")
            logs = _logs(docker, spec, workspace, failed)
            problems = [_check_line(c) for c in failed] + ([logs] if logs else [])
            _save_attempt(
                workspace,
                name,
                number,
                draft=draft,
                spec=spec,
                problems={"checks": [_check_line(c) for c in failed]},
                logs=logs,
            )
            _stop(down, name, workspace, docker)
            result.attempts.append(Attempt(number, "live", problems, components))
        return finish("failed", f"no working range after {max_attempts} attempts")
    except RefusalError as exc:
        return finish("refused", str(exc))
    except LLMError as exc:
        return finish("environment", str(exc))
    except HostEnvironmentError as exc:
        return finish("environment", str(exc))


def _adopt(
    edited: RangeSpec,
    result: BuildResult,
    conversation: Conversation,
    report: Reporter,
    workspace: Workspace,
    docker: Docker,
    ranges: Path,
) -> RangeSpec:
    """Start from the range the user edited; a new name must still be unique."""
    if edited.name != result.name:
        name = unique_name(edited.name, workspace=workspace, docker=docker, ranges=ranges)
        if name != edited.name:
            report("warn", f"a range named {edited.name} exists: this one is {name}")
            edited = edited.model_copy(update={"name": name})
        result.name = name
    conversation.adopt(edited)
    result.spec = edited
    return edited


def _stop(down: Callable[..., None], name: str, workspace: Workspace, docker: Docker) -> None:
    with contextlib.suppress(RangeError):  # nothing was started
        down(name, report=lambda level, text: None, workspace=workspace, docker=docker)


def _publish(result: BuildResult, spec: RangeSpec, workspace: Workspace, ranges: Path) -> None:
    """Write ranges/<name>/range.yaml and SCENARIO.md, and point the state at them."""
    folder = ranges / spec.name
    folder.mkdir(parents=True, exist_ok=True)
    range_file = folder / RANGE_FILE
    range_file.write_text(spec.to_yaml(), encoding="utf-8")
    scenario = folder / "SCENARIO.md"
    source = workspace.scenario_file(spec.name)
    if source.is_file():
        shutil.copy2(source, scenario)
    record = state_store.load(workspace.root).get(spec.name)
    if record is not None:
        updated = state_store.RangeState(**{**record.__dict__, "source": str(range_file.resolve())})
        state_store.record(workspace.root, updated)
    result.range_file = range_file
    result.scenario_file = scenario

"""What `sosya mcp` does, without MCP: plain functions over the same code the CLI uses.

Every function returns a Pydantic result with `ok` and readable `issues`, and never raises for
a problem of the range, Docker or the LLM. Rules that hold for every tool:

- dangerous environments are always refused: no argument overrides it, and they can only be
  started from the CLI, with `--allow-privileged` and a person confirming;
- the working directory is fixed (`default_root`), never the current directory, because MCP
  clients start servers from directories that may be read-only, such as `/`;
- nothing here writes to stdout, which belongs to the protocol: every Docker call captures its
  output, and progress goes through the `report` callback.
"""

import hmac
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel

from sosya import build as builder
from sosya import engine, gallery, runtime
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex, Entry
from sosya.catalog.search import search
from sosya.render import project_name
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker, DockerError
from sosya.spec import (
    EMULATED,
    RANGE_FILE,
    Issue,
    RangeSpec,
    SpecError,
    check_catalog,
    issues_from,
    load_range,
    parse_range,
)
from sosya.validate import Check
from sosya.validate import validate as run_validation

WORKSPACE_ENV = "SOSYA_WORKSPACE"
LLM_ENV = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL")
MAX_OUTPUT = 64_000
"""Characters kept of each of stdout and stderr of `attacker_exec`."""
MAX_EXEC_TIMEOUT = 600
REFUSED = (
    "the MCP server never starts environments with host-level privileges: they start only from "
    "the CLI, with `sosya up --allow-privileged` and a person confirming"
)
_FLAG = re.compile(r"SOSYA\{[^}\s]*\}")
REDACTED = "SOSYA{redacted}"

Report = Callable[[str, str], None]
"""(level, text): one progress step. Levels as in `sosya.runtime.Level`."""


def default_root(env: Mapping[str, str] | None = None) -> Path:
    """`SOSYA_WORKSPACE`, else `$XDG_STATE_HOME/sosya`, else `~/.local/state/sosya`."""
    env = os.environ if env is None else env
    if env.get(WORKSPACE_ENV):
        return Path(env[WORKSPACE_ENV]).expanduser()
    state = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(state) / "sosya"


def llm_configured(env: Mapping[str, str] | None = None) -> bool:
    """True when the environment names an LLM provider. No network call: the model is chosen
    at the first `new`, so the server starts at once, even offline."""
    env = os.environ if env is None else env
    return any(env.get(name) for name in LLM_ENV)


# --- results -------------------------------------------------------------------------------


class IssueOut(BaseModel):
    level: Literal["error", "warning"]
    message: str
    host: str = ""

    @classmethod
    def of(cls, issue: Issue) -> "IssueOut":
        return cls(level=issue.level, message=issue.message, host=issue.host)


class Result(BaseModel):
    ok: bool = True
    issues: list[IssueOut] = []


class PortOut(BaseModel):
    port: int
    protocol: str
    optional: bool = False


class SearchHit(BaseModel):
    id: str
    title: str
    cves: list[str]
    ports: list[PortOut]
    platforms: list[str] | None
    runnable: bool
    """The images can run on the engine's platform, natively or under emulation."""
    emulated: bool
    """They run only under emulation: slow, and sometimes broken."""
    needs_local_files: bool


class SearchResult(Result):
    engine_platform: str | None = None
    hits: list[SearchHit] = []


class CheckResult(Result):
    name: str | None = None


class UpResult(Result):
    name: str | None = None
    scenario_file: str | None = None
    flag_paths: dict[str, str] = {}
    attacker_exec: bool = False
    """Whether `attacker_exec` is allowed on this range (only with `attacker.internet: false`)."""


class ServiceOut(BaseModel):
    service: str
    host: str
    role: str
    state: str
    health: str | None


class RangeOut(BaseModel):
    name: str
    running: bool
    location: str
    services: list[ServiceOut]


class StatusResult(Result):
    ranges: list[RangeOut] = []


class CheckOut(BaseModel):
    group: str
    target: str
    ok: bool
    level: str
    detail: str
    host: str


class ValidateResult(Result):
    name: str = ""
    passed: int = 0
    total: int = 0
    checks: list[CheckOut] = []


class ScenarioResult(Result):
    name: str = ""
    text: str = ""


class NewResult(Result):
    outcome: str = ""
    name: str = ""
    range_yaml: str = ""
    scenario_file: str | None = None
    attempts: int = 0


class ExecResult(Result):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False


class FlagResult(Result):
    correct: bool | None = None


def failure(*messages: str, host: str = "", result: type[Result] = Result, **data: Any) -> Any:
    issues = [IssueOut(level="error", message=message, host=host) for message in messages]
    return result(ok=False, issues=issues, **data)


def redact(text: str, values: list[str]) -> str:
    for value in values:
        if value:
            text = text.replace(value, REDACTED)
    return _FLAG.sub(REDACTED, text)


# --- the tools -----------------------------------------------------------------------------


@dataclass
class Tools:
    root: Path = field(default_factory=default_root)
    docker: Docker = field(default_factory=Docker)
    index: CatalogIndex | None = None
    platform: Callable[[], str | None] = engine.docker_platform
    env: Mapping[str, str] = field(default_factory=lambda: os.environ)
    up_fn: Callable[..., state_store.RangeState] = runtime.up
    down_fn: Callable[..., None] = runtime.down
    status_fn: Callable[..., list[runtime.RangeStatus]] = runtime.status
    validate_fn: Callable[..., list[Check]] = run_validation
    build_fn: Callable[..., builder.BuildResult] = builder.build
    select_llm: Callable[..., Any] | None = None

    def __post_init__(self) -> None:
        self.root = self.root.expanduser().resolve()

    # paths

    @property
    def workspace(self) -> runtime.Workspace:
        return runtime.Workspace(self.root / ".sosya")

    @property
    def ranges(self) -> Path:
        return self.root / "ranges"

    def agent_file(self, name: str) -> Path:
        return self.root / "mcp" / name / RANGE_FILE

    def catalog(self) -> CatalogIndex:
        if self.index is None:
            self.index = load_index()
        return self.index

    def flag_values(self) -> list[str]:
        """Every flag value recorded in this workspace, for redaction."""
        records = state_store.load(self.workspace.root)
        return [f.get("value", "") for r in records.values() for f in r.flags.values()]

    # catalog and static checks

    def catalog_search(self, queries: list[str], limit: int = 10) -> SearchResult:
        index = self.catalog()
        host = self.platform()
        hits = search(index, queries, limit=None, include_dangerous=False)
        # `search` keeps a dangerous entry that a query names: the MCP server never shows one.
        entries = [hit.entry for hit in hits if not hit.entry.is_dangerous][: max(limit, 0)]
        return SearchResult(engine_platform=host, hits=[_hit(entry, host) for entry in entries])

    def _check(self, spec: RangeSpec) -> list[IssueOut]:
        index = self.catalog()
        issues = check_catalog(
            spec,
            index,
            host_platform=self.platform(),
            allow_privileged=True,  # the refusal below replaces the CLI's consent message
            services_of=load_services,
        )
        out = [IssueOut.of(i) for i in issues if "host-level privileges" not in i.message]
        for host in spec.hosts:
            entry = index.get(host.component)
            if entry is not None and entry.is_dangerous:
                reasons = "; ".join(f"{d.service}: {d.reason}" for d in entry.dangerous)
                message = f"{entry.id} gets host-level privileges ({reasons}); {REFUSED}"
                out.append(IssueOut(level="error", message=message, host=host.name))
        return out

    def _parse(self, range_yaml: str) -> tuple[RangeSpec | None, list[IssueOut]]:
        try:
            data = yaml.safe_load(range_yaml)
        except yaml.YAMLError as exc:
            return None, [IssueOut(level="error", message=f"range.yaml is not valid YAML: {exc}")]
        try:
            spec = parse_range(data, RANGE_FILE)
        except SpecError as exc:
            return None, [IssueOut.of(issue) for issue in issues_from(exc)]
        return spec, self._check(spec)

    def check_range(self, range_yaml: str) -> CheckResult:
        spec, issues = self._parse(range_yaml)
        ok = spec is not None and not any(i.level == "error" for i in issues)
        return CheckResult(ok=ok, issues=issues, name=spec.name if spec else None)

    # lifecycle

    def up(
        self, range_yaml: str | None = None, gallery_name: str | None = None, *, report: Report
    ) -> UpResult:
        if (range_yaml is None) == (gallery_name is None):
            return failure("pass exactly one of range_yaml and gallery", result=UpResult)
        if gallery_name is not None:
            folder = gallery.path(gallery_name)
            if folder is None:
                names = ", ".join(gallery.names())
                return failure(
                    f"no gallery range {gallery_name!r} (there are {names})", result=UpResult
                )
            range_yaml = (folder / RANGE_FILE).read_text(encoding="utf-8")
        assert range_yaml is not None
        spec, issues = self._parse(range_yaml)
        if spec is None or any(i.level == "error" for i in issues):
            return UpResult(ok=False, issues=issues, name=spec.name if spec else None)
        source = self.agent_file(spec.name)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(spec.to_yaml(), encoding="utf-8")
        try:
            record = self.up_fn(
                source,
                report=report,
                confirm=lambda lines: False,
                allow_privileged=False,
                workspace=self.workspace,
                docker=self.docker,
            )
        except (runtime.RangeError, DockerError) as exc:
            return failure(str(exc), result=UpResult, name=spec.name)
        warnings = [i for i in issues if i.level == "warning"]
        return UpResult(
            issues=warnings,
            name=spec.name,
            scenario_file=str(self.workspace.scenario_file(spec.name)),
            flag_paths={host: flag["path"] for host, flag in record.flags.items()},
            attacker_exec=not spec.attacker.internet,
        )

    def status(self) -> StatusResult:
        try:
            ranges = self.status_fn(workspace=self.workspace, docker=self.docker)
        except DockerError as exc:
            return failure(str(exc), result=StatusResult)
        return StatusResult(
            ranges=[
                RangeOut(
                    name=r.name,
                    running=r.running,
                    location=r.location,
                    services=[ServiceOut(**s.__dict__) for s in r.services],
                )
                for r in ranges
            ]
        )

    def validate(self, name: str) -> ValidateResult:
        try:
            checks = self.validate_fn(name, workspace=self.workspace, docker=self.docker)
        except (runtime.RangeError, DockerError) as exc:
            return failure(str(exc), result=ValidateResult, name=name)
        counted = [c for c in checks if c.level == "check"]
        failed = [c for c in counted if not c.ok]
        return ValidateResult(
            ok=not failed,
            issues=[
                IssueOut(level="error", message=f"{c.group} {c.target}: {c.detail}", host=c.host)
                for c in failed
            ]
            + [
                IssueOut(level="warning", message=f"{c.group} {c.target}: {c.detail}", host=c.host)
                for c in checks
                if c.level == "warning" and not c.ok
            ],
            name=name,
            passed=len(counted) - len(failed),
            total=len(counted),
            checks=[CheckOut(**c.__dict__) for c in checks],
        )

    def down(self, name: str) -> Result:
        try:
            self.down_fn(
                name, report=lambda level, text: None, workspace=self.workspace, docker=self.docker
            )
        except (runtime.RangeError, DockerError) as exc:
            return failure(str(exc))
        return Result()

    def scenario(self, name: str) -> ScenarioResult:
        path = self.workspace.scenario_file(name)
        if not path.is_file():
            return failure(
                f"no SCENARIO.md for {name}: start the range with `up` first",
                result=ScenarioResult,
                name=name,
            )
        return ScenarioResult(name=name, text=path.read_text(encoding="utf-8"))

    def new(self, description: str, *, report: Report) -> NewResult:
        from sosya import llm

        try:
            adapter = (self.select_llm or llm.select)(env=self.env)
        except llm.LLMError as exc:
            return failure(str(exc), result=NewResult)

        def phase(name: str, text: str) -> None:
            report("ok", f"{name}: {text}")

        try:
            result = self.build_fn(
                description,
                adapter,
                report=report,
                phase=phase,
                confirm_plan=lambda spec, result: True,
                confirm_privileged=lambda lines: False,
                allow_privileged=False,
                workspace=self.workspace,
                docker=self.docker,
                ranges=self.ranges,
            )
        except (runtime.RangeError, DockerError) as exc:
            return failure(str(exc), result=NewResult)
        data: dict[str, Any] = {
            "outcome": result.outcome,
            "name": result.name,
            "attempts": len(result.attempts),
        }
        if result.outcome == "green" and result.spec is not None:
            return NewResult(
                range_yaml=result.spec.to_yaml(),
                scenario_file=str(result.scenario_file) if result.scenario_file else None,
                **data,
            )
        messages = [result.message or f"the build ended with {result.outcome}"]
        if result.outcome == "dangerous":
            messages = [*result.dangerous, REFUSED]
        return failure(*messages, result=NewResult, **data)

    # inside the range

    def _recorded(self, name: str) -> tuple[state_store.RangeState | None, str]:
        record = state_store.load(self.workspace.root).get(name)
        if record is None:
            return None, f"no range named {name} was started by this MCP server"
        return record, ""

    def attacker_exec(self, name: str, command: str, timeout: int = 60) -> ExecResult:
        record, problem = self._recorded(name)
        if record is None:
            return failure(problem, result=ExecResult)
        try:
            spec = load_range(Path(record.source))
        except SpecError as exc:
            return failure(str(exc), result=ExecResult)
        if spec.attacker.internet:
            return failure(
                f"attacker_exec is allowed only on ranges with `attacker.internet: false`: the "
                f"attacker box of {name} can reach the internet, and an agent must not be able "
                "to use it against the internet",
                result=ExecResult,
            )
        try:
            box, problem = self._attacker_box(name)
            if box is None:
                return failure(problem, result=ExecResult)
            seconds = min(max(int(timeout), 1), MAX_EXEC_TIMEOUT)
            proc = self.docker.run(["exec", box, "bash", "-lc", command], timeout=seconds)
        except DockerError as exc:
            return failure(str(exc), result=ExecResult)
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        truncated = len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
        return ExecResult(
            exit_code=proc.returncode,
            stdout=stdout[-MAX_OUTPUT:],
            stderr=stderr[-MAX_OUTPUT:],
            truncated=truncated,
        )

    def _attacker_box(self, name: str) -> tuple[str | None, str]:
        """The running attacker box's id, after checking live that every network it joins is
        internal: a tampered state file must not be enough to get a box with internet access.
        Returns (id, "") or (None, problem)."""
        found = self.docker.containers(project_name(name))
        boxes = [c for c in found if c.role == "attacker" and c.state == "running"]
        if not boxes:
            return None, f"the attacker box of {name} is not running"
        box = boxes[0].id
        proc = self.docker.run(["inspect", box])
        if proc.returncode != 0:
            return None, f"cannot inspect the attacker box of {name}"
        inspected = json.loads(proc.stdout or "[]")
        if not inspected:
            return None, f"cannot inspect the attacker box of {name}"
        data = inspected[0]
        networks = list((data.get("NetworkSettings") or {}).get("Networks") or {})
        if not networks:
            return None, f"the attacker box of {name} joins no network"
        proc = self.docker.run(["network", "inspect", *networks])
        if proc.returncode != 0:
            return None, f"cannot inspect the networks of the attacker box of {name}"
        open_networks = [
            n.get("Name", "?") for n in json.loads(proc.stdout) if not n.get("Internal")
        ]
        if open_networks:
            return None, (
                f"the attacker box of {name} joins networks that are not internal "
                f"({', '.join(open_networks)}): attacker_exec is refused"
            )
        return box, ""

    def check_flag(self, name: str, host: str, value: str) -> FlagResult:
        record, problem = self._recorded(name)
        if record is None:
            return failure(problem, result=FlagResult)
        flag = record.flags.get(host)
        if flag is None:
            hosts = ", ".join(sorted(record.flags)) or "none"
            return failure(
                f"no flag was placed on host {host!r} of {name} (hosts with a flag: {hosts})",
                result=FlagResult,
            )
        correct = hmac.compare_digest(value.strip().encode(), flag["value"].encode())
        return FlagResult(correct=correct)


def _hit(entry: Entry, host: str | None) -> SearchHit:
    platforms = entry.platforms
    native = bool(host and platforms and host in platforms)
    emulated = bool(host and platforms and not native and EMULATED.get(host) in platforms)
    return SearchHit(
        id=entry.id,
        title=entry.title,
        cves=entry.cves,
        ports=[
            PortOut(port=p.port, protocol=p.protocol, optional=p.optional)
            for s in entry.services
            for p in s.ports
        ],
        platforms=platforms,
        runnable=native or emulated or (host is None and bool(platforms)),
        emulated=emulated,
        needs_local_files=not entry.image_only,
    )

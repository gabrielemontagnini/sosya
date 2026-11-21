"""Command-line interface for Sosya."""

import time
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from sosya import __version__, gallery, runtime
from sosya.catalog.display import host_platform, results_json, results_table
from sosya.catalog.loader import load_index
from sosya.catalog.search import DEFAULT_LIMIT, search
from sosya.doctor import CheckResult, Status, run_checks
from sosya.spec import RANGE_FILE, SpecError, load_range

app = typer.Typer(
    name="sosya",
    help="Describe a hacking lab in plain English. Get it running, isolated and verified.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

RangeArg = Annotated[
    str, typer.Argument(metavar="RANGE", help="Range name or path to a range.yaml.")
]

_STATUS_LABEL = {
    Status.OK: "[green]ok[/]",
    Status.WARN: "[yellow]warn[/]",
    Status.FAIL: "[red]fail[/]",
}


def _version(value: bool) -> None:
    if value:
        console.print(f"sosya {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Sosya builds isolated, verified security labs from a single sentence."""


_NEXT = {
    "queries": "searching the catalog",
    "candidates": "planning the range",
    "plan": "starting the containers",
    "up": "validating",
    "validate": "planning a repair",
}
_PHASE_WIDTH = 10


def _duration(seconds: float) -> str:
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes}m{rest:02d}s" if minutes else f"{rest}s"


def _plan_table(spec, result) -> Table:
    emulated = {c.entry.id for c in result.candidates if c.emulated}
    dangerous = {line.split(":", 1)[0] for line in result.dangerous}
    table = Table(title=f"plan: {spec.name}", title_justify="left", header_style="bold")
    for column in ("Host", "Component", "Networks", "Notes"):
        table.add_column(column)
    for host in spec.hosts:
        notes = []
        if host.name in dangerous:
            notes.append("[bold red]! host-level privileges[/]")
        if host.component in emulated:
            notes.append("[yellow]emulated: slow[/]")
        table.add_row(
            host.name,
            host.component.removeprefix("vulhub/"),
            ", ".join(host.networks),
            " ".join(notes),
        )
    internet = "internet" if spec.attacker.internet else "no internet"
    table.add_row("attacker", "Kali attacker box", ", ".join(spec.attacker.networks), internet)
    return table


@app.command()
def new(
    description: Annotated[str, typer.Argument(help="The lab you want, in plain English.")],
    model: Annotated[
        str | None, typer.Option(help="LLM model id. Default: SOSYA_MODEL, else automatic.")
    ] = None,
    effort: Annotated[
        str | None, typer.Option(help="Reasoning effort: low, medium, high, xhigh or max.")
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Start the plan without asking first.")
    ] = False,
    allow_privileged: Annotated[
        bool,
        typer.Option(
            "--allow-privileged",
            help="Allow environments that get host-level privileges, after a confirmation.",
        ),
    ] = False,
) -> None:
    """Plan a range from a description, then start, validate and repair it."""
    from sosya import build as builder
    from sosya import engine, llm

    problem = engine.engine_problem()
    if problem is not None:
        _fail(runtime.RangeError(problem))
    try:
        adapter = llm.select(model, effort)
    except llm.LLMError as exc:
        _fail(exc)

    status = console.status("reading the description")

    def phase(name: str, text: str) -> None:
        console.print(f"{_MARKS['ok']} {name:<{_PHASE_WIDTH}} {text}", highlight=False)
        status.update(_NEXT.get(name, "working"))

    def ask(spec, result) -> bool:
        if yes:
            return True
        status.stop()
        console.print(_plan_table(spec, result))
        answer = typer.confirm("Start this range?", default=True)
        status.start()
        return answer

    def ask_privileged(lines: list[str]) -> bool:
        status.stop()
        answer = _confirm_privileged(lines)
        status.start()
        return answer

    with status:
        result = builder.build(
            description,
            adapter,
            report=_report,
            phase=phase,
            confirm_plan=ask,
            confirm_privileged=ask_privileged,
            allow_privileged=allow_privileged,
            effort=effort,
        )
    if result.outcome == "dangerous" and result.spec is not None:
        console.print(_plan_table(result.spec, result))
        for line in result.dangerous:
            console.print(f"     [red]![/] {line}", highlight=False)
    total = _duration(result.total)
    if result.outcome != "green":
        _report("fail", f"{result.message} ({total})")
        if result.attempts and result.name:
            folder = runtime.Workspace().attempts_dir(result.name)
            console.print(f"     [dim]attempts kept in {folder}[/]", highlight=False)
        raise typer.Exit(code=1)
    _report("ok", f"ready {result.name} in {total}")
    console.print(f"     sosya shell {result.name}", highlight=False)
    console.print(f"     scenario: {result.scenario_file}", highlight=False)


_MARKS = {
    "ok": "[green]ok[/]  ",
    "warn": "[yellow]warn[/]",
    "fail": "[red]fail[/]",
    "info": "[dim]··[/]  ",
}


def _report(level: runtime.Level, text: str) -> None:
    console.print(f"{_MARKS[level]} {text}", highlight=False)


def _fail(exc: Exception) -> NoReturn:
    _report("fail", str(exc))
    raise typer.Exit(code=1)


def _range_path(target: str) -> Path:
    """Find a range, in this order: a path, a name recorded here, ranges/<name>, the gallery."""
    path = Path(target)
    if path.exists():
        return path
    record = runtime.state_store.load(runtime.WORKSPACE).get(target)
    if record is not None and Path(record.source).exists():
        return Path(record.source)
    candidate = Path("ranges") / target
    if (candidate / RANGE_FILE).is_file():
        return candidate
    shipped = gallery.path(target)
    if shipped is not None:
        return shipped
    available = ", ".join(gallery.names())
    _fail(
        SpecError(
            f"no range.yaml at {target}, no range named {target} here or under ranges/, "
            f"and none in the gallery ({available})"
        )
    )


def _range_name(target: str) -> str:
    """A range name, or the name inside the range.yaml that `target` points to."""
    path = Path(target)
    if path.exists():
        try:
            return load_range(path).name
        except SpecError as exc:
            _fail(exc)
    return target


def _confirm_privileged(lines: list[str]) -> bool:
    console.print("[bold red]warn[/] these services get host-level privileges:")
    for line in lines:
        console.print(f"     [red]![/] {line}", highlight=False)
    return typer.confirm("Start them anyway?", default=False)


@app.command()
def up(
    target: RangeArg,
    allow_privileged: Annotated[
        bool,
        typer.Option(
            "--allow-privileged",
            help="Allow environments that get host-level privileges, after a confirmation.",
        ),
    ] = False,
) -> None:
    """Start a range from its range.yaml. No LLM needed."""
    try:
        runtime.up(
            _range_path(target),
            report=_report,
            confirm=_confirm_privileged,
            allow_privileged=allow_privileged,
        )
    except (runtime.RangeError, runtime.DockerError) as exc:
        _fail(exc)


@app.command()
def down(target: RangeArg) -> None:
    """Stop a range and remove its containers and networks."""
    try:
        runtime.down(_range_name(target), report=_report)
    except (runtime.RangeError, runtime.DockerError) as exc:
        _fail(exc)


@app.command()
def status() -> None:
    """List running ranges and the health of their services."""
    try:
        ranges = runtime.status()
    except runtime.DockerError as exc:
        _fail(exc)
    if not ranges:
        console.print("No ranges. Start one with [bold]sosya up <range>[/].")
        return
    table = Table(title="sosya status", title_justify="left", header_style="bold")
    for column in ("Range", "Service", "Role", "State", "Health"):
        table.add_column(column)
    for item in ranges:
        if not item.services:
            table.add_row(item.name, "", "", "[dim]stopped[/]", "")
        for i, service in enumerate(item.services):
            color = "green" if service.state == "running" else "yellow"
            health = service.health or ""
            if health:
                health = f"[{'green' if health == 'healthy' else 'yellow'}]{health}[/]"
            table.add_row(
                item.name if i == 0 else "",
                service.service,
                service.role,
                f"[{color}]{service.state}[/]",
                health,
            )
    console.print(table)
    for item in ranges:
        if not item.local and item.location:
            console.print(f"[dim]{item.name} was started from {item.location}[/]")


@app.command()
def shell(target: RangeArg) -> None:
    """Open a shell in the range's Kali attacker box."""
    try:
        code = runtime.shell(_range_name(target))
    except (runtime.RangeError, runtime.DockerError) as exc:
        _fail(exc)
    raise typer.Exit(code=code)


@app.command()
def validate(target: RangeArg) -> None:
    """Re-run every check on a running range: services, reachability, isolation and flags."""
    from sosya import validate as checks_module

    name = _range_name(target)
    started = time.monotonic()
    try:
        with console.status(f"validating {name}"):
            checks = checks_module.validate(name)
    except (runtime.RangeError, runtime.DockerError) as exc:
        _fail(exc)
    console.print(validation_table(name, checks))
    failed = checks_module.failures(checks)
    elapsed = time.monotonic() - started
    passed = sum(1 for check in checks if check.level == "check" and check.ok)
    total = sum(1 for check in checks if check.level == "check")
    if failed:
        _report("fail", f"{len(failed)} of {total} checks failed ({elapsed:.0f}s)")
        raise typer.Exit(code=1)
    _report("ok", f"{passed}/{total} checks passed ({elapsed:.0f}s)")


def validation_table(name: str, checks: list) -> Table:
    table = Table(title=f"sosya validate {name}", title_justify="left", header_style="bold")
    for column in ("Check", "Target", "Result", "Detail"):
        table.add_column(column)
    for check in checks:
        if check.ok:
            result = "[green]ok[/]"
        elif check.level == "warning":
            result = "[yellow]warn[/]"
        else:
            result = "[red]fail[/]"
        table.add_row(check.group, check.target, result, check.detail)
    return table


@app.command()
def catalog(
    queries: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="[QUERY]...",
            help="What to search for. Each argument is a separate query and the results are "
            "merged: `sosya catalog jenkins gitlab`. Quote words that belong together: "
            '`sosya catalog "java deserialization"`.',
        ),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option(
            help="Show at most this many results. Default: 25 for a search, all for none."
        ),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the results as JSON.")] = False,
) -> None:
    """Search the available vulnerable environments."""
    index = load_index()
    has_query = any(query.strip() for query in queries or [])
    hits = search(
        index,
        queries or [],
        limit=limit if limit is not None else (DEFAULT_LIMIT if has_query else None),
        include_dangerous=True,
    )
    if as_json:
        typer.echo(results_json(hits))
        return
    if not hits:
        console.print(f"No environment matches [bold]{' '.join(queries or [])}[/].")
        return
    console.print(results_table(hits, host_platform()))
    console.print(
        f"[dim]{len(hits)} of {len(index.entries)} environments · "
        f"Vulhub @ {index.vulhub_commit[:7]}[/]"
    )


@app.command()
def doctor() -> None:
    """Check Docker, Compose v2, CPU architecture and LLM configuration."""
    results = run_checks()
    _print_checks(results)
    if any(result.status is Status.FAIL for result in results):
        raise typer.Exit(code=1)


def _print_checks(results: list[CheckResult]) -> None:
    table = Table(title="sosya doctor", title_justify="left", header_style="bold")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details", overflow="fold")
    for result in results:
        table.add_row(result.name, _STATUS_LABEL[result.status], result.detail)
    console.print(table)

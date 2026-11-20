"""Command-line interface for Sosya."""

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sosya import __version__
from sosya.doctor import CheckResult, Status, run_checks

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


def _not_yet(command: str) -> None:
    console.print(f"[yellow]sosya {command}[/] is not implemented yet: it is planned for v0.1.")
    raise typer.Exit(code=1)


@app.command()
def new(
    description: Annotated[str, typer.Argument(help="The lab you want, in plain English.")],
) -> None:
    """Plan a range from a description, then build and validate it."""
    _not_yet("new")


@app.command()
def up(name: RangeArg) -> None:
    """Start a range from its range.yaml. No LLM needed."""
    _not_yet("up")


@app.command()
def down(name: RangeArg) -> None:
    """Stop a range and remove its containers and networks."""
    _not_yet("down")


@app.command()
def status() -> None:
    """List running ranges and the health of their services."""
    _not_yet("status")


@app.command()
def shell(name: RangeArg) -> None:
    """Open a shell in the range's Kali attacker box."""
    _not_yet("shell")


@app.command()
def validate(name: RangeArg) -> None:
    """Re-run every check on an existing range."""
    _not_yet("validate")


@app.command()
def catalog(
    query: Annotated[str | None, typer.Argument(help="Words to search for.")] = None,
) -> None:
    """Search the available vulnerable environments."""
    _not_yet("catalog")


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

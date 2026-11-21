"""The MCP server: a thin layer that registers `sosya.mcp.tools` as MCP tools.

Every result is returned both as structured content and as JSON text, and marked as an error
when `ok` is false. Flag values are redacted from every result and progress message, except
the output of `attacker_exec`: there a flag only appears when an agent really exploited a
target, and redacting it would stop the agent from proving the capture. `check_flag` answers
right or wrong without ever revealing a value.
"""

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import anyio
import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import CallToolResult, TextContent
from pydantic import Field

from sosya import __version__
from sosya.mcp import tools as t

log = logging.getLogger("sosya.mcp")

INSTRUCTIONS = """\
Sosya builds isolated, verified security labs ("ranges") from public Vulhub environments.

You can act as the planner yourself, without an LLM key: search the catalog with
`catalog_search`, write a range.yaml (apiVersion sosya/v1) from the ids it returns, check it with
`check_range` until it has no errors, then start it with `up`. `validate` re-runs the isolation
and reachability checks, `scenario` returns the objectives and hints, `down` removes the range.
`up` also accepts the name of a gallery range, such as dmz-redis.

`attacker_exec` runs a command in the range's attacker box, only for ranges with
`attacker.internet: false`. Submit a captured flag with `check_flag`. Environments with
host-level privileges are always refused: they start only from the CLI, with a person confirming.
"""

Queries = Annotated[list[str], Field(description="Search terms; several queries are merged.")]
Name = Annotated[str, Field(description="The range name, as in its range.yaml.")]


def _reply(result: t.Result, values: list[str] | None) -> CallToolResult:
    """`values` None means no redaction (attacker_exec)."""
    text = result.model_dump_json(indent=1)
    if values is not None:
        text = t.redact(text, values)
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=json.loads(text),
        is_error=not result.ok,
    )


def _safe(work: Callable[[], t.Result]) -> t.Result:
    """Any unexpected exception becomes a readable issue, and its traceback goes to stderr."""
    try:
        return work()
    except Exception as exc:
        log.exception("tool failed")
        return t.failure(f"internal error: {type(exc).__name__}: {exc}")


async def _run(work: Callable[[], t.Result]) -> t.Result:
    return await anyio.to_thread.run_sync(lambda: _safe(work))


async def _with_progress(
    ctx: Context, work: Callable[[t.Report], t.Result], values: Callable[[], list[str]]
) -> t.Result:
    """Run a blocking tool in a thread; every step it reports becomes a progress notification."""
    step = 0

    def report(level: str, text: str) -> None:
        nonlocal step
        step += 1
        message = t.redact(f"{level}: {text}", values())
        log.info(message)
        anyio.from_thread.run(ctx.report_progress, step, None, message)

    return await _run(lambda: work(report))


def build_server(tools: t.Tools, *, with_new: bool | None = None) -> MCPServer:
    """The server for `tools`. `new` is registered only when an LLM is configured."""
    server = MCPServer("sosya", version=__version__, instructions=INSTRUCTIONS)
    values = tools.flag_values

    @server.tool()
    async def catalog_search(
        queries: Queries, limit: int = 10
    ) -> Annotated[CallToolResult, t.SearchResult]:
        """Search the Vulhub catalog. Returns ids, titles, CVEs, ports, platforms and whether
        each environment runs on this engine (natively or under emulation). Environments with
        host-level privileges are never listed."""
        result = await _run(lambda: tools.catalog_search(queries, limit))
        return _reply(result, values())

    @server.tool()
    async def check_range(range_yaml: str) -> Annotated[CallToolResult, t.CheckResult]:
        """Check a range.yaml you wrote: schema, catalog, names and platforms. Returns the same
        issues as Sosya's own repair loop. Fix every error, then call `up`."""
        result = await _run(lambda: tools.check_range(range_yaml))
        return _reply(result, values())

    @server.tool()
    async def up(
        ctx: Context, range_yaml: str | None = None, gallery: str | None = None
    ) -> Annotated[CallToolResult, t.UpResult]:
        """Start a range from a range.yaml, or from the name of a gallery range (pass exactly
        one). Pulls images, starts the containers and places the flags; reports progress."""
        result = await _with_progress(
            ctx, lambda report: tools.up(range_yaml, gallery, report=report), values
        )
        return _reply(result, values())

    @server.tool()
    async def status() -> Annotated[CallToolResult, t.StatusResult]:
        """List the ranges and the state of their services."""
        result = await _run(tools.status)
        return _reply(result, values())

    @server.tool()
    async def validate(ctx: Context, name: Name) -> Annotated[CallToolResult, t.ValidateResult]:
        """Re-run every check on a running range: services, reachability, segmentation, no
        internet for targets, host isolation and flags."""
        result = await _with_progress(ctx, lambda report: tools.validate(name), values)
        return _reply(result, values())

    @server.tool()
    async def down(name: Name) -> Annotated[CallToolResult, t.Result]:
        """Stop a range and remove its containers, networks and files."""
        result = await _run(lambda: tools.down(name))
        return _reply(result, values())

    @server.tool()
    async def scenario(name: Name) -> Annotated[CallToolResult, t.ScenarioResult]:
        """The range's SCENARIO.md: objectives, network map, flag paths and progressive hints."""
        result = await _run(lambda: tools.scenario(name))
        return _reply(result, values())

    @server.tool()
    async def attacker_exec(
        name: Name, command: str, timeout: int = 60
    ) -> Annotated[CallToolResult, t.ExecResult]:
        """Run a shell command in the range's attacker box and return its output. Allowed only
        for ranges with `attacker.internet: false`, so the box cannot be used against the
        internet."""
        result = await _run(lambda: tools.attacker_exec(name, command, timeout))
        return _reply(result, None)

    @server.tool()
    async def check_flag(
        name: Name, host: str, value: str
    ) -> Annotated[CallToolResult, t.FlagResult]:
        """Check a captured flag. Answers only whether it is correct; never reveals a value."""
        result = await _run(lambda: tools.check_flag(name, host, value))
        return _reply(result, values())

    if with_new if with_new is not None else t.llm_configured(tools.env):

        @server.tool()
        async def new(ctx: Context, description: str) -> Annotated[CallToolResult, t.NewResult]:
            """Plan a range from one sentence with Sosya's own LLM planner, then start, validate
            and repair it (at most 3 attempts). Takes minutes; reports progress."""
            result = await _with_progress(
                ctx, lambda report: tools.new(description, report=report), values
            )
            return _reply(result, values())

    return server


def run_stdio(root: Path | None = None) -> None:
    """Serve on stdio. Logs go to stderr: stdout belongs to the protocol."""
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    workspace = root or t.default_root()
    workspace.mkdir(parents=True, exist_ok=True)
    tools = t.Tools(root=workspace)
    log.info("workspace %s", tools.root)
    build_server(tools).run("stdio")


__all__ = ["build_server", "run_stdio"]

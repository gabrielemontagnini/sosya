"""The MCP server, through an in-process MCP client. No Docker, no network, no LLM."""

import json
import subprocess
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp import Client
from test_runtime import DMZ_REDIS, FakeDocker, container, done

from sosya import attacker, engine
from sosya.build import BuildResult
from sosya.catalog.loader import load_index
from sosya.mcp import server as mcp_server
from sosya.mcp import tools as mcp_tools
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker
from sosya.scenario import flags

DANGEROUS = """\
apiVersion: sosya/v1
name: dangerous
networks: [lab]
hosts:
  - name: dock
    component: vulhub/docker/unauthorized-rce
    networks: [lab]
attacker:
  networks: [lab]
"""
OFFLINE = DMZ_REDIS.replace("  networks: [dmz]\n", "  networks: [dmz]\n  internet: false\n")


class Harness:
    def __init__(self, root: Path, env: dict[str, str] | None = None) -> None:
        self.fake = FakeDocker()
        self.built: list[dict[str, Any]] = []
        self.build_result = BuildResult(outcome="failed", message="no plan")
        self.tools = mcp_tools.Tools(
            root=root,
            docker=Docker(runner=self.fake),
            index=load_index(),
            platform=lambda: "linux/amd64",
            env=env or {},
            build_fn=self.build,
            select_llm=lambda **kwargs: object(),
        )

    def build(self, sentence: str, llm: Any, **kwargs: Any) -> BuildResult:
        self.built.append({"sentence": sentence, **kwargs})
        kwargs["phase"]("queries", "struts2")
        return self.build_result

    def server(self, **kwargs: Any):
        return mcp_server.build_server(self.tools, **kwargs)

    def record(self, source: str, values: dict[str, str], name: str = "dmz-redis") -> None:
        path = self.tools.root / "mcp" / name / "range.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        state_store.record(
            self.tools.workspace.root,
            state_store.RangeState(
                name=name,
                project=f"sosya-{name}",
                compose_file=str(self.tools.workspace.compose_file(name)),
                source=str(path),
                started_at="t",
                flags={h: {"path": "/flag.txt", "value": v} for h, v in values.items()},
            ),
        )

    def call(self, tool: str, arguments: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        return call(self.server(**kwargs), tool, arguments)


class Reply:
    """A tool result and the progress notifications that came before it."""

    def __init__(self, result: Any, progress: list[tuple[float, str | None]]) -> None:
        self.is_error = result.is_error
        self.content = result.content
        self.structured_content = result.structured_content
        self.progress = progress


def call(server: Any, tool: str, arguments: dict[str, Any] | None = None) -> Any:
    progress: list[tuple[float, str | None]] = []

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        progress.append((value, message))

    async def run() -> Any:
        async with Client(server) as client:
            return await client.call_tool(tool, arguments or {}, progress_callback=on_progress)

    return Reply(anyio.run(run), progress)


def tool_names(server: Any) -> set[str]:
    async def run() -> set[str]:
        async with Client(server) as client:
            return {tool.name for tool in (await client.list_tools()).tools}

    return anyio.run(run)


def text(result: Any) -> str:
    return "\n".join(block.text for block in result.content) + json.dumps(result.structured_content)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    monkeypatch.setattr(engine, "engine_problem", lambda: None)
    monkeypatch.setattr(engine, "docker_platform", lambda: "linux/amd64")
    monkeypatch.delenv(attacker.IMAGE_ENV, raising=False)
    monkeypatch.chdir(tmp_path)  # a stray relative path would land here, and be noticed
    return Harness(tmp_path / "state")


BASE_TOOLS = {
    "catalog_search",
    "check_range",
    "up",
    "status",
    "validate",
    "down",
    "scenario",
    "attacker_exec",
    "check_flag",
}


def test_new_is_listed_only_with_an_llm_configuration(tmp_path: Path) -> None:
    assert tool_names(Harness(tmp_path).server()) == BASE_TOOLS
    configured = Harness(tmp_path, env={"OPENAI_BASE_URL": "http://localhost:11434/v1"})
    assert tool_names(configured.server()) == BASE_TOOLS | {"new"}


def test_llm_configuration_is_read_without_network() -> None:
    assert not mcp_tools.llm_configured({})
    assert mcp_tools.llm_configured({"ANTHROPIC_API_KEY": "sk-x"})


def test_workspace_is_fixed_never_the_current_directory(tmp_path: Path) -> None:
    assert mcp_tools.default_root({"SOSYA_WORKSPACE": str(tmp_path)}) == tmp_path
    assert mcp_tools.default_root({"XDG_STATE_HOME": "/s"}) == Path("/s/sosya")
    assert mcp_tools.default_root({}) == Path.home() / ".local" / "state" / "sosya"


# --- catalog and checks --------------------------------------------------------------------


def test_catalog_search_never_lists_dangerous_entries(harness: Harness) -> None:
    for query in (["docker unauthorized rce"], ["ingress-nginx", "CVE-2025-1974"]):
        result = harness.call("catalog_search", {"queries": query, "limit": 50})
        ids = [hit["id"] for hit in result.structured_content["hits"]]
        assert "vulhub/docker/unauthorized-rce" not in ids
        assert "vulhub/ingress-nginx/CVE-2025-1974" not in ids


def test_catalog_search_shows_ports_platforms_and_emulation(harness: Harness) -> None:
    result = harness.call("catalog_search", {"queries": ["jenkins CVE-2017-1000353"]})
    assert not result.is_error
    hit = next(
        h for h in result.structured_content["hits"] if h["id"] == "vulhub/jenkins/CVE-2017-1000353"
    )
    assert {"port": 50000, "protocol": "tcp", "optional": True} in hit["ports"]
    assert hit["platforms"] == ["linux/amd64"]
    assert hit["runnable"] and not hit["emulated"]
    assert result.structured_content["engine_platform"] == "linux/amd64"


def test_check_range_accepts_a_good_range(harness: Harness) -> None:
    result = harness.call("check_range", {"range_yaml": DMZ_REDIS})
    assert not result.is_error
    assert result.structured_content["ok"] and result.structured_content["name"] == "dmz-redis"


def test_check_range_returns_readable_issues(harness: Harness) -> None:
    broken = DMZ_REDIS.replace("vulhub/redis/4-unacc", "vulhub/redis/4-unauth")
    result = harness.call("check_range", {"range_yaml": broken})
    assert result.is_error
    (issue,) = result.structured_content["issues"]
    assert issue["host"] == "cache" and "Did you mean vulhub/redis/4-unacc" in issue["message"]

    result = harness.call("check_range", {"range_yaml": "apiVersion: [unclosed"})
    assert "not valid YAML" in result.structured_content["issues"][0]["message"]

    result = harness.call("check_range", {"range_yaml": DMZ_REDIS.replace("[dmz]\n", "[nope]\n")})
    messages = [i["message"] for i in result.structured_content["issues"]]
    assert any("undeclared networks: nope" in m for m in messages)


def test_dangerous_ranges_are_refused_by_check_and_up(harness: Harness) -> None:
    for tool in ("check_range", "up"):
        result = harness.call(tool, {"range_yaml": DANGEROUS})
        assert result.is_error
        (issue,) = result.structured_content["issues"]
        assert "host-level privileges" in issue["message"]
        assert "only from the CLI" in issue["message"]
    assert harness.fake.calls == []  # nothing was started, not even looked at


# --- lifecycle -----------------------------------------------------------------------------


def test_up_from_the_gallery_reports_progress(harness: Harness) -> None:
    harness.fake.missing_images = {"vulhub/struts2:2.3.30"}
    result = harness.call("up", {"gallery": "dmz-redis"})
    assert not result.is_error, text(result)
    data = result.structured_content
    assert data["name"] == "dmz-redis" and data["attacker_exec"] is False
    assert len(result.progress) >= 5
    assert [step for step, _ in result.progress] == list(range(1, len(result.progress) + 1))
    messages = " ".join(message or "" for _, message in result.progress)
    assert "pulling" in messages and "range dmz-redis is up" in messages
    assert (harness.tools.root / "mcp" / "dmz-redis" / "range.yaml").is_file()
    assert (harness.tools.root / ".sosya" / "state.json").is_file()
    assert not (Path.cwd() / ".sosya").exists()
    up = harness.fake.commands("compose", "-p", "sosya-dmz-redis")
    assert any("up" in argv for argv in up)


def test_up_from_an_agent_yaml_keeps_it_outside_the_range_dir(harness: Harness) -> None:
    result = harness.call("up", {"range_yaml": OFFLINE})
    assert not result.is_error, text(result)
    assert result.structured_content["attacker_exec"] is True
    record = state_store.load(harness.tools.workspace.root)["dmz-redis"]
    assert record.source == str(harness.tools.root / "mcp" / "dmz-redis" / "range.yaml")


def test_up_needs_exactly_one_source(harness: Harness) -> None:
    for arguments in ({}, {"range_yaml": DMZ_REDIS, "gallery": "dmz-redis"}):
        result = harness.call("up", arguments)
        assert result.is_error and "exactly one" in text(result)
    result = harness.call("up", {"gallery": "nope"})
    assert result.is_error and "no gallery range" in text(result)


def test_up_failures_come_back_as_issues(harness: Harness) -> None:
    harness.fake.on(
        lambda a: a[:1] == ["compose"] and "up" in a, lambda a: done(code=1, stderr="boom")
    )
    result = harness.call("up", {"gallery": "dmz-redis"})
    assert result.is_error
    assert "docker compose up failed" in result.structured_content["issues"][0]["message"]


def test_status_validate_scenario_and_down(harness: Harness) -> None:
    value = flags.new_flag()
    harness.record(DMZ_REDIS, {"web": value})
    scenario = harness.tools.workspace.scenario_file("dmz-redis")
    scenario.parent.mkdir(parents=True, exist_ok=True)
    scenario.write_text(f"# dmz-redis\n\nflag on web at /flag.txt, never {value}\n")
    harness.fake.containers = [container("web"), container("attacker", role="attacker")]

    status = harness.call("status")
    assert not status.is_error
    (item,) = status.structured_content["ranges"]
    assert item["name"] == "dmz-redis" and item["running"]

    result = harness.call("scenario", {"name": "dmz-redis"})
    assert "flag on web at /flag.txt" in result.structured_content["text"]
    assert value not in text(result) and "SOSYA{redacted}" in text(result)

    missing = harness.call("scenario", {"name": "other"})
    assert missing.is_error and "start the range with `up`" in text(missing)

    result = harness.call("validate", {"name": "dmz-redis"})
    assert "total" in result.structured_content
    assert value not in text(result)

    result = harness.call("down", {"name": "dmz-redis"})
    assert not result.is_error, text(result)
    assert "dmz-redis" not in state_store.load(harness.tools.workspace.root)


def test_validate_of_an_unknown_range_is_an_issue(harness: Harness) -> None:
    result = harness.call("validate", {"name": "nope"})
    assert result.is_error and "no range named nope" in text(result)


# --- new -----------------------------------------------------------------------------------


def test_new_never_allows_privileged_environments(tmp_path: Path) -> None:
    harness = Harness(tmp_path, env={"ANTHROPIC_API_KEY": "sk-x"})
    harness.build_result = BuildResult(
        outcome="dangerous", message="needs --allow-privileged", dangerous=["dock: privileged"]
    )
    result = harness.call("new", {"description": "a docker daemon with no auth"})
    assert result.is_error
    assert "only from the CLI" in text(result)
    (built,) = harness.built
    assert built["allow_privileged"] is False
    assert built["confirm_privileged"](["x"]) is False
    assert built["ranges"] == harness.tools.root / "ranges"
    assert result.progress and "queries: struts2" in result.progress[0][1]


def test_new_returns_the_green_range(tmp_path: Path) -> None:
    import yaml

    from sosya.spec import parse_range

    harness = Harness(tmp_path, env={"ANTHROPIC_API_KEY": "sk-x"})
    spec = parse_range(yaml.safe_load(DMZ_REDIS))
    harness.build_result = BuildResult(outcome="green", name="dmz-redis", spec=spec)
    result = harness.call("new", {"description": "struts and redis"})
    assert not result.is_error
    assert "vulhub/struts2/s2-045" in result.structured_content["range_yaml"]


# --- attacker_exec and check_flag ----------------------------------------------------------


def _live_attacker(harness: Harness, networks: dict[str, bool]) -> None:
    box = container("attacker", role="attacker")
    box["NetworkSettings"] = {"Networks": {name: {} for name in networks}}
    harness.fake.containers = [box]
    harness.fake.on(  # docker accepts the short ids that ContainerInfo keeps
        lambda a: a[:1] == ["inspect"],
        lambda a: done(json.dumps([box] if box["Id"].startswith(a[1]) else [])),
    )
    harness.fake.on(
        lambda a: a[:2] == ["network", "inspect"],
        lambda a: done(json.dumps([{"Name": n, "Internal": networks[n]} for n in a[2:]])),
    )


def test_attacker_exec_needs_a_range_without_internet(harness: Harness) -> None:
    harness.record(DMZ_REDIS, {})
    result = harness.call("attacker_exec", {"name": "dmz-redis", "command": "id"})
    assert result.is_error and "attacker.internet: false" in text(result)
    assert harness.fake.commands("exec") == []


def test_attacker_exec_checks_the_live_networks(harness: Harness) -> None:
    harness.record(OFFLINE, {})  # the state says no internet...
    _live_attacker(harness, {"sosya-dmz-redis_dmz": True, "sosya-dmz-redis_egress": False})
    result = harness.call("attacker_exec", {"name": "dmz-redis", "command": "id"})
    assert result.is_error and "not internal" in text(result)  # ...but the box has it
    assert harness.fake.commands("exec") == []


def test_attacker_exec_returns_the_output_unredacted(harness: Harness) -> None:
    value = flags.new_flag()
    harness.record(OFFLINE, {"cache": value})
    _live_attacker(harness, {"sosya-dmz-redis_dmz": True})
    harness.fake.on(lambda a: a[:1] == ["exec"], lambda a: done(f"{value}\n", stderr="warn"))
    result = harness.call(
        "attacker_exec", {"name": "dmz-redis", "command": "redis-cli -h cache get flag"}
    )
    assert not result.is_error, text(result)
    assert result.structured_content["stdout"] == f"{value}\n"
    assert result.structured_content["exit_code"] == 0
    (argv,) = harness.fake.commands("exec")
    assert argv[-3:] == ["bash", "-lc", "redis-cli -h cache get flag"]


def test_check_flag_answers_right_or_wrong_and_never_reveals(harness: Harness) -> None:
    value = flags.new_flag()
    harness.record(DMZ_REDIS, {"web": value})
    answers = {
        "right": harness.call("check_flag", {"name": "dmz-redis", "host": "web", "value": value}),
        "wrong": harness.call(
            "check_flag", {"name": "dmz-redis", "host": "web", "value": flags.new_flag()}
        ),
        "host": harness.call("check_flag", {"name": "dmz-redis", "host": "db", "value": value}),
        "range": harness.call("check_flag", {"name": "nope", "host": "web", "value": value}),
    }
    assert answers["right"].structured_content["correct"] is True
    assert answers["wrong"].structured_content["correct"] is False
    assert answers["host"].is_error and "hosts with a flag: web" in text(answers["host"])
    assert answers["range"].is_error
    for result in answers.values():
        assert value not in text(result)


def test_no_management_tool_returns_a_flag_value(harness: Harness) -> None:
    value = flags.new_flag()
    harness.record(DMZ_REDIS, {"web": value})
    harness.fake.on(lambda a: a[:1] == ["ps"], lambda a: done(stderr=f"weird {value}", code=1))
    for tool, arguments in (("status", {}), ("down", {"name": "dmz-redis"})):
        result = harness.call(tool, arguments)
        assert value not in text(result), tool


def test_redact_replaces_recorded_values_and_the_flag_shape() -> None:
    assert mcp_tools.redact("a SOSYA{abc} b", []) == "a SOSYA{redacted} b"
    assert mcp_tools.redact("x secret y", ["secret"]) == "x SOSYA{redacted} y"


def test_subprocess_output_is_always_captured(harness: Harness) -> None:
    """stdout belongs to the protocol: no Docker call of a tool may inherit it."""
    seen: list[dict[str, Any]] = []
    original = harness.fake.__call__

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(kwargs)
        return original(argv, **kwargs)

    harness.tools.docker = Docker(runner=runner)
    harness.call("up", {"gallery": "dmz-redis"})
    assert seen and all(kwargs.get("capture_output") for kwargs in seen)

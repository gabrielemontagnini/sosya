import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from sosya import __version__, runtime
from sosya.cli import app

runner = CliRunner()

COMMANDS = ("new", "up", "down", "status", "shell", "validate", "catalog", "doctor")


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in COMMANDS:
        assert command in result.output


def test_catalog_search_shows_a_table() -> None:
    result = runner.invoke(app, ["catalog", "CVE-2017-5638"])
    assert result.exit_code == 0
    assert "struts2/s2-045" in result.output
    assert "of 334 environments" in result.output


def test_catalog_merges_several_queries() -> None:
    result = runner.invoke(app, ["catalog", "--json", "--limit", "10", "jenkins", "gitlab"])
    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert 0 < len(hits) <= 10
    products = {hit["entry"]["product_dir"] for hit in hits}
    assert {"jenkins", "gitlab"} <= products


def test_catalog_marks_dangerous_environments() -> None:
    result = runner.invoke(app, ["catalog", "docker/unauthorized-rce"])
    assert result.exit_code == 0
    assert "privileged" in result.output


def test_catalog_without_query_lists_everything() -> None:
    result = runner.invoke(app, ["catalog", "--json"])
    assert len(json.loads(result.output)) == 334


def test_catalog_with_no_match() -> None:
    result = runner.invoke(app, ["catalog", "zzzzqqq"])
    assert result.exit_code == 0
    assert "No environment matches" in result.output


RANGE = """\
apiVersion: sosya/v1
name: lab
networks: [dmz]
hosts:
  - name: web
    component: vulhub/struts2/s2-045
    networks: [dmz]
attacker:
  networks: [dmz]
"""


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "lab").mkdir()
    (tmp_path / "lab" / "range.yaml").write_text(RANGE)
    return tmp_path / "lab"


def test_up_passes_the_path_and_prints_steps(lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_up(path: Path, *, report, confirm, allow_privileged: bool) -> None:
        seen.update(path=path, allow_privileged=allow_privileged)
        report("ok", "range lab is up")

    monkeypatch.setattr(runtime, "up", fake_up)
    result = runner.invoke(app, ["up", "lab", "--allow-privileged"])
    assert result.exit_code == 0, result.output
    assert seen == {"path": Path("lab"), "allow_privileged": True}
    assert "ok" in result.output and "range lab is up" in result.output


def test_up_failure_exits_with_one(lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_up(path: Path, **kwargs: Any) -> None:
        raise runtime.RangeError("Docker Engine 27.5.1 is too old")

    monkeypatch.setattr(runtime, "up", fake_up)
    result = runner.invoke(app, ["up", "lab"])
    assert result.exit_code == 1
    assert "fail" in result.output and "too old" in result.output


def test_up_of_an_unknown_range(lab: Path) -> None:
    result = runner.invoke(app, ["up", "nowhere"])
    assert result.exit_code == 1
    assert "no range named nowhere" in result.output


def test_down_and_shell_accept_a_path_or_a_name(lab: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    names: list[str] = []
    monkeypatch.setattr(runtime, "down", lambda name, report: names.append(name))
    monkeypatch.setattr(runtime, "shell", lambda name: names.append(name) or 3)
    assert runner.invoke(app, ["down", "lab"]).exit_code == 0  # the directory: its range name
    assert runner.invoke(app, ["down", "far-away"]).exit_code == 0  # a name only
    assert runner.invoke(app, ["shell", "lab/range.yaml"]).exit_code == 3
    assert names == ["lab", "far-away", "lab"]


def test_status_shows_every_range(monkeypatch: pytest.MonkeyPatch) -> None:
    ranges = [
        runtime.RangeStatus(
            name="lab",
            project="sosya-lab",
            location="/work/.sosya/ranges/lab",
            local=False,
            services=[
                runtime.ServiceStatus("attacker", "attacker", "attacker", "running", None),
                runtime.ServiceStatus("web", "web", "target", "running", "healthy"),
            ],
        )
    ]
    monkeypatch.setattr(runtime, "status", lambda: ranges)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "lab" in result.output and "healthy" in result.output
    assert "started from /work/.sosya/ranges/lab" in result.output


def test_status_without_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "status", lambda: [])
    assert "No ranges" in runner.invoke(app, ["status"]).output


def test_validate_prints_a_table_and_fails_on_a_failed_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sosya import validate as checks_module
    from sosya.validate import Check

    results = [
        Check("reach", "web:8080", True, "reachable"),
        Check("attacker", "internet access", False, "failed", level="warning"),
    ]
    monkeypatch.setattr(checks_module, "validate", lambda name: results)
    result = runner.invoke(app, ["validate", "lab"])
    assert result.exit_code == 0, result.output
    assert "web:8080" in result.output and "warn" in result.output
    assert "1/1 checks passed" in result.output

    results.append(Check("flag", "web", False, "/flag.txt missing or changed"))
    result = runner.invoke(app, ["validate", "lab"])
    assert result.exit_code == 1
    assert "1 of 2 checks failed" in result.output


def test_validate_of_a_range_that_is_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    from sosya import validate as checks_module

    def missing(name: str):
        raise runtime.RangeError(f"no range named {name} was started from this directory")

    monkeypatch.setattr(checks_module, "validate", missing)
    result = runner.invoke(app, ["validate", "ghost"])
    assert result.exit_code == 1
    assert "no range named ghost" in result.output


# --- new ------------------------------------------------------------------------------------


def fake_new(monkeypatch: pytest.MonkeyPatch, outcome: str = "green", **extra: Any) -> dict:
    from sosya import build as builder
    from sosya import engine, llm
    from sosya.spec import parse_range

    seen: dict[str, Any] = {}
    monkeypatch.setattr(engine, "engine_problem", lambda: None)
    monkeypatch.setattr(llm, "select", lambda model, effort: "fake-llm")
    spec = parse_range(
        {
            "apiVersion": "sosya/v1",
            "name": "lab",
            "networks": ["dmz"],
            "hosts": [{"name": "web", "component": "vulhub/struts2/s2-045", "networks": ["dmz"]}],
            "attacker": {"networks": ["dmz"]},
        }
    )

    def build(
        sentence,
        adapter,
        *,
        report,
        phase,
        confirm_plan,
        confirm_privileged,
        allow_privileged,
        effort,
    ):
        seen.update(sentence=sentence, allow_privileged=allow_privileged, effort=effort)
        phase("queries", "struts2")
        phase("candidates", "12")
        result = builder.BuildResult(outcome="green", name="lab", spec=spec)
        seen["confirmed"] = confirm_plan(spec, result)
        if outcome == "green" and seen["confirmed"]:
            phase("plan", "attempt 1: web=struts2/s2-045")
            phase("up", "1 host(s) running")
            phase("validate", "14/14 checks passed")
            result.scenario_file = Path("ranges/lab/SCENARIO.md")
        else:
            result.outcome = outcome if seen["confirmed"] else "cancelled"
            result.message = extra.get("message", "cancelled: nothing was started")
        result.phases["total"] = 102.0
        result.dangerous = extra.get("dangerous", [])
        return result

    monkeypatch.setattr(builder, "build", build)
    return seen


def test_new_prints_one_line_per_phase_and_the_total(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = fake_new(monkeypatch)
    result = runner.invoke(app, ["new", "a struts2 lab", "--yes", "--effort", "low"])
    assert result.exit_code == 0, result.output
    assert seen == {
        "sentence": "a struts2 lab",
        "allow_privileged": False,
        "effort": "low",
        "confirmed": True,
    }
    lines = [line for line in result.output.splitlines() if line.startswith("ok")]
    assert [line.split()[1] for line in lines[:5]] == [
        "queries",
        "candidates",
        "plan",
        "up",
        "validate",
    ]
    assert "ready lab in 1m42s" in result.output
    assert "sosya shell lab" in result.output
    assert "ranges/lab/SCENARIO.md" in result.output
    assert "plan: lab" not in result.output  # --yes skips the preview table


def test_new_asks_before_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_new(monkeypatch)
    result = runner.invoke(app, ["new", "a struts2 lab"], input="n\n")
    assert result.exit_code == 1
    assert "plan: lab" in result.output and "Start this range?" in result.output
    assert "cancelled" in result.output


def test_new_stops_on_dangerous_plans(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_new(
        monkeypatch,
        outcome="dangerous",
        message="the plan needs environments with host-level privileges: run again with "
        "--allow-privileged",
        dangerous=["web: vulhub/x gets host-level privileges (x: privileged)"],
    )
    result = runner.invoke(app, ["new", "x", "--yes"])
    assert result.exit_code == 1
    assert "--allow-privileged" in result.output
    assert "host-level privileges" in result.output


def test_new_without_an_llm_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from sosya import engine

    monkeypatch.setattr(engine, "engine_problem", lambda: None)
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL", "SOSYA_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    result = runner.invoke(app, ["new", "x"])
    assert result.exit_code == 1
    assert "no LLM provider is configured" in result.output
    assert "sosya up" in result.output


def test_new_needs_docker_first(monkeypatch: pytest.MonkeyPatch) -> None:
    result = runner.invoke(app, ["new", "x"])
    assert result.exit_code == 1
    assert "Docker daemon is not reachable" in result.output

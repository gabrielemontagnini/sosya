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


def test_unimplemented_command_fails_clearly() -> None:
    result = runner.invoke(app, ["new", "a struts2 lab"])
    assert result.exit_code == 1
    assert "not implemented yet" in result.output


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

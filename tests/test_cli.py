import json

from typer.testing import CliRunner

from sosya import __version__
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
    result = runner.invoke(app, ["status"])
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

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

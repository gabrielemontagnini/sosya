import subprocess

import pytest

from sosya import engine


def answer(stdout: str, code: int = 0):
    def run(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, code, stdout, "")

    return run


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("linux/x86_64\n", "linux/amd64"),
        ("linux/aarch64\n", "linux/arm64"),
        ("linux/armv7l\n", "linux/arm/v7"),
        ("linux/riscv64\n", None),
    ],
)
def test_platform_comes_from_the_daemon(
    monkeypatch: pytest.MonkeyPatch, stdout: str, expected: str | None
) -> None:
    monkeypatch.setattr(engine, "run", answer(stdout))
    assert engine.docker_platform() == expected


def test_unreachable_daemon_has_no_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "run", answer("", code=1))
    assert engine.docker_platform() is None


def test_catalog_display_prefers_the_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    from sosya.catalog import display

    monkeypatch.setattr(display.platform, "machine", lambda: "x86_64")
    assert display.host_platform() == "linux/amd64"  # daemon unreachable: Python's guess
    monkeypatch.setattr(engine, "run", answer("linux/aarch64\n"))
    assert display.host_platform() == "linux/arm64"

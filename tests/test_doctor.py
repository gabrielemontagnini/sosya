import subprocess

import pytest

from sosya import doctor
from sosya.doctor import Status


def _fake_run(returncode: int = 0, stdout: str = "", stderr: str = ""):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return run


@pytest.fixture
def docker_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")


def test_missing_docker_fails_every_docker_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.check_docker_cli().status is Status.FAIL
    assert doctor.check_docker_daemon().status is Status.FAIL
    assert doctor.check_compose().status is Status.FAIL


@pytest.mark.usefixtures("docker_on_path")
def test_compose_version_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.subprocess, "run", _fake_run(stdout="2.40.0\n"))
    result = doctor.check_compose()
    assert result.status is Status.OK
    assert result.detail == "2.40.0"


@pytest.mark.usefixtures("docker_on_path")
def test_unreachable_daemon_fails_with_its_error(monkeypatch: pytest.MonkeyPatch) -> None:
    error = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
    monkeypatch.setattr(doctor.subprocess, "run", _fake_run(returncode=1, stderr=error))
    result = doctor.check_docker_daemon()
    assert result.status is Status.FAIL
    assert "Cannot connect" in result.detail


@pytest.mark.usefixtures("docker_on_path")
def test_daemon_timeout_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout=10)

    monkeypatch.setattr(doctor.subprocess, "run", hang)
    assert doctor.check_docker_daemon().status is Status.FAIL


@pytest.mark.parametrize(("machine", "expected"), [("x86_64", Status.OK), ("arm64", Status.WARN)])
def test_architecture_falls_back_to_the_machine(
    monkeypatch: pytest.MonkeyPatch, machine: str, expected: Status
) -> None:
    monkeypatch.setattr(doctor.platform, "machine", lambda: machine)
    result = doctor.check_architecture()
    assert result.status is expected
    assert "Docker not reachable" in result.detail


def test_architecture_comes_from_the_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    # An x86_64 Python (under Rosetta, or with a remote context) talking to an arm64 engine.
    monkeypatch.setattr(doctor.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(doctor.engine, "docker_platform", lambda: "linux/arm64")
    result = doctor.check_architecture()
    assert result.status is Status.WARN
    assert result.detail.startswith("linux/arm64 (Docker Engine)")


@pytest.mark.usefixtures("docker_on_path")
@pytest.mark.parametrize(
    ("version", "expected"),
    [("29.10.0", Status.OK), ("28.0.0", Status.OK), ("27.5.1", Status.FAIL)],
)
def test_engine_older_than_28_fails(
    monkeypatch: pytest.MonkeyPatch, version: str, expected: Status
) -> None:
    monkeypatch.setattr(doctor.subprocess, "run", _fake_run(stdout=f"{version}\n"))
    result = doctor.check_docker_daemon()
    assert result.status is expected
    if expected is Status.FAIL:
        assert "28.0.0 or newer" in result.detail


def test_missing_git_is_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert doctor.check_git().status is Status.WARN


def test_llm_key_values_are_never_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in doctor.LLM_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret-value")
    result = doctor.check_llm()
    assert result.status is Status.OK
    assert "sk-test-secret-value" not in result.detail


def test_no_llm_is_only_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in doctor.LLM_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    assert doctor.check_llm().status is Status.WARN

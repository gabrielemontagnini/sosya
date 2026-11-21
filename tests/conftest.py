import subprocess
from pathlib import Path

import pytest
from test_runtime import DMZ_REDIS, FakeDocker

from sosya import attacker, engine, runtime


@pytest.fixture(autouse=True)
def no_docker_engine(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests never talk to Docker: the engine looks unreachable unless a test says so."""
    if request.node.get_closest_marker("docker"):
        return

    def unreachable(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "Cannot connect to the Docker daemon")

    monkeypatch.setattr(engine, "run", unreachable)


@pytest.fixture
def fake() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> runtime.Workspace:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(engine, "engine_problem", lambda: None)
    monkeypatch.setattr(engine, "docker_platform", lambda: "linux/amd64")
    monkeypatch.delenv(attacker.IMAGE_ENV, raising=False)
    return runtime.Workspace(tmp_path / ".sosya")


@pytest.fixture
def range_dir(tmp_path: Path) -> Path:
    path = tmp_path / "examples" / "dmz-redis"
    path.mkdir(parents=True)
    (path / "range.yaml").write_text(DMZ_REDIS)
    return path

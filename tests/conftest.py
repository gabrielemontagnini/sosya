import subprocess

import pytest

from sosya import engine


@pytest.fixture(autouse=True)
def no_docker_engine(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests never talk to Docker: the engine looks unreachable unless a test says so."""
    if request.node.get_closest_marker("docker"):
        return

    def unreachable(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "Cannot connect to the Docker daemon")

    monkeypatch.setattr(engine, "run", unreachable)

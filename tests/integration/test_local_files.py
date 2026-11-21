"""A live range whose environment bind-mounts files from the Vulhub checkout.

`nginx/insecure-configuration` is the lightest image-only environment with directory binds
(`vulhub/nginx:1`, about 45 MB compressed). The test downloads its Vulhub directory, starts the
range, writes into a bind mount as root from inside the container, and stops the range. Nothing
may be left behind, not even the root-owned files, and the shared Vulhub cache must be unchanged.

Run with `uv run pytest -m docker`. Needs Docker Engine 28+, git and network access.
"""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from sosya import runtime
from sosya.catalog.loader import load_index
from sosya.runtime import vulhub
from sosya.runtime.docker import Docker

pytestmark = pytest.mark.docker

COMPONENT = "vulhub/nginx/insecure-configuration"
NAME = "bind-check"
PROJECT = f"sosya-{NAME}"
RANGE = f"""\
apiVersion: sosya/v1
name: {NAME}
networks: [lan]
hosts:
  - name: web
    component: {COMPONENT}
    networks: [lan]
attacker:
  networks: [lan]
  internet: false
"""


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def fingerprint(root: Path) -> list[tuple[str, int, str]]:
    """Every path under `root` with its mode and, for files, the sha256 of its content."""
    items = []
    for path in sorted(root.rglob("*")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        items.append((str(path.relative_to(root)), path.lstat().st_mode, digest))
    return items


def leftovers() -> dict[str, list[str]]:
    found = {
        "containers": docker(
            "ps", "--all", "--quiet", "--filter", f"label=sosya.range={NAME}"
        ).stdout.split(),
        "networks": docker(
            "network", "ls", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"
        ).stdout.split(),
        "volumes": docker(
            "volume", "ls", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"
        ).stdout.split(),
    }
    return {kind: ids for kind, ids in found.items() if ids}


def test_bind_mounts_are_copied_written_and_cleaned_up(tmp_path: Path) -> None:
    entry = load_index().get(COMPONENT)
    assert entry is not None and not entry.image_only
    checkout = vulhub.ensure([entry.path])
    before = fingerprint(checkout / entry.path)
    assert before

    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "range.yaml").write_text(RANGE)
    workspace = runtime.Workspace(tmp_path / ".sosya")
    files = workspace.files_dir(NAME) / "web"
    try:
        runtime.up(
            lab, report=lambda level, text: None, confirm=lambda lines: False, workspace=workspace
        )
        (target,) = [c for c in Docker().containers(PROJECT) if c.role == "target"]
        write = docker(
            "exec",
            "--user",
            "0",
            target.id,
            "sh",
            "-c",
            "mkdir -p /usr/share/nginx/html/rootdir && echo pwned > /usr/share/nginx/html/rootdir/x"
            " && echo pwned > /usr/share/nginx/html/root.txt",
        )
        assert write.returncode == 0, write.stderr
        written = files / "www" / "root.txt"
        assert written.read_text() == "pwned\n"
        assert written.stat().st_uid == 0
        assert (files / "www" / "rootdir").stat().st_uid == 0
        # The range got its own copy: the shared cache does not see the write.
        assert not (checkout / entry.path / "www" / "root.txt").exists()
    finally:
        runtime.down(NAME, report=lambda level, text: None, workspace=workspace)

    assert not workspace.range_dir(NAME).exists()
    assert leftovers() == {}
    assert fingerprint(checkout / entry.path) == before
    state = json.loads((workspace.root / "state.json").read_text())
    assert NAME not in state["ranges"]

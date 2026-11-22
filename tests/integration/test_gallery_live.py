"""Every gallery range, live: `sosya up`, `sosya validate` with no failure, `sosya down`.

Run by the weekly gallery workflow (`uv run pytest -m gallery`), so an upstream image that
disappears is noticed. CI on every push keeps to dmz-redis (`tests/integration/test_isolation.py`).
With `SOSYA_PRUNE_IMAGES=1`, each range's images are removed after it stops, keeping only the
attacker box image: CI runners have little disk space.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from sosya import attacker, gallery, runtime
from sosya.render import project_name
from sosya.runtime.docker import Docker
from sosya.validate import failures, validate

pytestmark = [pytest.mark.docker, pytest.mark.gallery]


def _images(project: str) -> set[str]:
    ids = [c.id for c in Docker().containers(project)]
    if not ids:
        return set()
    proc = subprocess.run(
        ["docker", "inspect", *ids], capture_output=True, text=True, check=False, timeout=60
    )
    if proc.returncode != 0:
        return set()
    return {item["Config"]["Image"] for item in json.loads(proc.stdout)}


def _prune(images: set[str]) -> None:
    keep = attacker.image()
    for image in sorted(images - {keep}):
        subprocess.run(
            ["docker", "image", "rm", "--force", image],
            capture_output=True,
            check=False,
            timeout=300,
        )


@pytest.mark.parametrize("name", gallery.names())
def test_gallery_range_is_green_live(name: str, tmp_path: Path) -> None:
    path = gallery.path(name)
    assert path is not None
    workspace = runtime.Workspace(tmp_path / ".sosya")
    images: set[str] = set()
    try:
        runtime.up(
            path, report=lambda level, text: None, confirm=lambda lines: False, workspace=workspace
        )
        images = _images(project_name(name))
        checks = validate(name, workspace=workspace)
        failed = [f"{c.group} {c.target}: {c.detail}" for c in failures(checks)]
        assert failed == []
    finally:
        runtime.down(name, report=lambda level, text: None, workspace=workspace)
        if os.environ.get("SOSYA_PRUNE_IMAGES") == "1":
            _prune(images)

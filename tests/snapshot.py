"""Minimal snapshot testing. `SOSYA_UPDATE_SNAPSHOTS=1 uv run pytest` rewrites the files."""

import os
from pathlib import Path

SNAPSHOTS = Path(__file__).parent / "snapshots"


def assert_snapshot(name: str, text: str) -> None:
    path = SNAPSHOTS / name
    if os.environ.get("SOSYA_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    assert path.is_file(), f"missing snapshot {path}: run with SOSYA_UPDATE_SNAPSHOTS=1"
    assert text == path.read_text(encoding="utf-8"), f"snapshot {name} changed"

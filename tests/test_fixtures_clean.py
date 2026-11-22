"""No tracked text file carries the word the repository refuses, and fixtures carry fake model ids.

The word the repository's pre-push hook refuses is built from character codes, so this file
does not contain it and the hook does not block the test itself. The same check runs here, in
`uv run pytest`, so a contributor without the hook (or a pull request from a fork) finds out
before review.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "llm"
FORBIDDEN = "".join(map(chr, (99, 108, 97, 117, 100, 101)))
FILES = sorted(FIXTURES.rglob("*.json"))


def test_there_are_fixtures() -> None:
    assert FILES


@pytest.mark.parametrize("path", FILES, ids=lambda path: path.name)
def test_fixture_has_no_real_model_id(path: Path) -> None:
    assert FORBIDDEN not in path.read_text(encoding="utf-8").lower()


def _tracked_files() -> list[Path] | None:
    """Every file git tracks, or None outside a git checkout (an unpacked sdist, for example)."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False, timeout=60
    )
    if proc.returncode != 0:
        return None
    return [ROOT / name for name in proc.stdout.decode().split("\0") if name]


def _text(path: Path) -> str | None:
    """The file's text, or None for a binary file or one deleted from the working tree."""
    try:
        data = path.read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def test_no_tracked_file_names_the_refused_word() -> None:
    files = _tracked_files()
    if files is None:
        pytest.skip("not a git checkout")
    assert files
    offenders = [
        str(path.relative_to(ROOT))
        for path in files
        if FORBIDDEN in str(path.relative_to(ROOT)).lower()
        or FORBIDDEN in (_text(path) or "").lower()
    ]
    assert offenders == [], "remove the refused word from: " + ", ".join(offenders)

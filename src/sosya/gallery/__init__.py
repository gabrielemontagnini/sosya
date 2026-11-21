"""Ready-made ranges shipped inside the package, so `sosya up <name>` works without a repository.

Each range lives in `sosya/gallery/<name>/range.yaml`. A clean install has no `examples/`
folder and no LLM key, but it can still start every gallery range.
"""

from importlib import resources
from pathlib import Path

from sosya.spec import RANGE_FILE


def _root() -> Path:
    # Wheels install as plain files, so the package directory is a real path on disk.
    return Path(str(resources.files("sosya.gallery")))


def names() -> list[str]:
    """The names of every gallery range, sorted."""
    return sorted(
        child.name
        for child in _root().iterdir()
        if child.is_dir() and (child / RANGE_FILE).is_file()
    )


def path(name: str) -> Path | None:
    """The directory of the gallery range `name`, or None if there is no such range."""
    if name not in names():
        return None
    return _root() / name

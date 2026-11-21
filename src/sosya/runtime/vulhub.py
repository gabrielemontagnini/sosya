"""On-demand download of Vulhub environment directories, for environments with local files.

The cache is a blobless, shallow, sparse clone at the pinned commit, shared by every range of
this user. It is only a read-only source: build contexts and env files are read from it, and
bind-mounted files are copied into each range before it starts.
"""

import os
from pathlib import Path

from sosya.catalog import VULHUB_COMMIT, VULHUB_URL
from sosya.catalog.git import GitError, git, head


def cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sosya" / "vulhub" / VULHUB_COMMIT


def _patterns(checkout: Path) -> list[str]:
    try:
        return [line for line in git(checkout, "sparse-checkout", "list").splitlines() if line]
    except GitError:
        return []


def ensure(paths: list[str], checkout: Path | None = None) -> Path:
    """Make sure every environment directory in `paths` is checked out; return the checkout."""
    checkout = checkout or cache_root()
    if head(checkout) == VULHUB_COMMIT and all((checkout / p).is_dir() for p in paths):
        return checkout
    checkout.mkdir(parents=True, exist_ok=True)
    if not (checkout / ".git").is_dir():
        git(checkout, "init", "--quiet")
        git(checkout, "remote", "add", "origin", VULHUB_URL)
        git(checkout, "config", "core.sparseCheckout", "true")
    wanted = sorted({*_patterns(checkout), *(f"/{path}/" for path in paths)})
    git(checkout, "sparse-checkout", "set", "--no-cone", *wanted)
    if head(checkout) != VULHUB_COMMIT:
        git(
            checkout,
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "--filter=blob:none",
            "origin",
            VULHUB_COMMIT,
        )
        git(checkout, "checkout", "--quiet", "--detach", VULHUB_COMMIT)
    missing = [path for path in paths if not (checkout / path).is_dir()]
    if missing:
        raise GitError(f"Vulhub checkout lacks {', '.join(missing)}")
    return checkout

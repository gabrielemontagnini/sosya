"""Development only: fetch the Vulhub catalog at the pinned commit.

The clone is blobless, shallow and sparse: it holds `environments.toml`, Vulhub's `LICENSE`
(shipped with the package) and, for each
environment, only its compose file, English README and Dockerfiles.
"""

import tomllib
from pathlib import Path

from sosya.catalog import VULHUB_COMMIT, VULHUB_URL
from sosya.catalog.git import GitError, git, head

DEFAULT_CHECKOUT = Path(".cache/vulhub")
ENV_FILES = ("docker-compose.yml", "README.md", "Dockerfile*")
TOP_FILES = ("environments.toml", "LICENSE")


SourceError = GitError
_git = git


def sparse_patterns(paths: list[str]) -> list[str]:
    patterns = ["/environments.toml", "/LICENSE"]
    for path in sorted(paths):
        patterns.extend(f"/{path}/{name}" for name in ENV_FILES)
    return patterns


def sync(checkout: Path = DEFAULT_CHECKOUT, commit: str = VULHUB_COMMIT) -> Path:
    """Make `checkout` a sparse checkout of Vulhub at `commit`. Idempotent."""
    if head(checkout) == commit and all((checkout / name).is_file() for name in TOP_FILES):
        return checkout
    checkout.mkdir(parents=True, exist_ok=True)
    if not (checkout / ".git").is_dir():
        _git(checkout, "init", "--quiet")
        _git(checkout, "remote", "add", "origin", VULHUB_URL)
    _git(checkout, "config", "core.sparseCheckout", "true")
    _git(checkout, "sparse-checkout", "set", "--no-cone", "/environments.toml")
    _git(checkout, "fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", commit)
    _git(checkout, "checkout", "--quiet", "--detach", commit)
    environments = tomllib.loads((checkout / "environments.toml").read_text(encoding="utf-8"))
    paths = [env["path"] for env in environments["environment"]]
    _git(checkout, "sparse-checkout", "set", "--no-cone", *sparse_patterns(paths))
    if head(checkout) != commit:
        raise SourceError(f"checkout is not at the pinned commit {commit}")
    return checkout

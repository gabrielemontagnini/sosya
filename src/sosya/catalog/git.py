"""Thin git helpers shared by the catalog builder and the on-demand Vulhub download."""

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def git(checkout: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(checkout), *args], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        raise GitError("git is not installed") from None
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def head(checkout: Path) -> str | None:
    if not (checkout / ".git").is_dir():
        return None
    try:
        return git(checkout, "rev-parse", "HEAD")
    except GitError:
        return None

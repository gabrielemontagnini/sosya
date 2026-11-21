"""The attacker box image: its name, and how to build it from the Dockerfile in the package.

Releases publish the image to GHCR, so `sosya up` only pulls it. Building is the fallback when
the pull fails, and takes a few minutes.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import resources
from pathlib import Path

from sosya import __version__

REPOSITORY = "ghcr.io/gabrielemontagnini/sosya-attacker"
IMAGE_ENV = "SOSYA_ATTACKER_IMAGE"


def image() -> str:
    """The image every range uses for its attacker box. `SOSYA_ATTACKER_IMAGE` overrides it."""
    return os.environ.get(IMAGE_ENV) or f"{REPOSITORY}:{__version__}"


@contextmanager
def build_context() -> Iterator[Path]:
    """The directory that holds the packaged Dockerfile."""
    with resources.as_file(resources.files("sosya.attacker")) as path:
        yield path


def build_command(tag: str, context: Path) -> list[str]:
    return ["docker", "build", "--tag", tag, str(context)]

"""Random flags, injected into running targets with `docker cp`, which needs no shell inside.

The archive holds only the flag file, never a directory entry, so extracting it does not change
the owner or mode of an existing directory such as `/root` or `/tmp`. The file is world-readable
(0644): several environments give only a file read or a shell that is not root.
"""

import io
import posixpath
import secrets
import tarfile
from dataclasses import dataclass

from sosya.runtime.docker import Docker

DEFAULT_PATH = "/flag.txt"
FALLBACK_PATH = "/tmp/flag.txt"
MODE = 0o644


@dataclass(frozen=True)
class Flag:
    path: str
    value: str


def new_flag() -> str:
    return "SOSYA{" + secrets.token_hex(16) + "}"


def archive(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        info.mode = MODE
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def read_archive(data: bytes) -> bytes | None:
    """The content of the single file in a `docker cp ... -` archive."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    handle = tar.extractfile(member)
                    return handle.read() if handle else None
    except tarfile.TarError:
        return None
    return None


def place(docker: Docker, container: str, wanted: str | None) -> Flag | None:
    """Write a new flag at `wanted` (default /flag.txt), else at /tmp/flag.txt. None if neither."""
    value = new_flag()
    content = (value + "\n").encode()
    paths = [wanted or DEFAULT_PATH]
    if FALLBACK_PATH not in paths:
        paths.append(FALLBACK_PATH)
    for path in paths:
        directory, name = posixpath.split(path)
        if docker.copy_in(container, directory or "/", archive(name, content)):
            return Flag(path, value)
    return None


def read(docker: Docker, container: str, path: str) -> str | None:
    data = docker.copy_out(container, path)
    if data is None:
        return None
    content = read_archive(data)
    return content.decode(errors="replace").strip() if content is not None else None

"""Facts about the Docker Engine that Sosya talks to, read from the daemon itself.

Python's `platform.machine()` describes the interpreter, not the engine: it is wrong for an
x86_64 Python under Rosetta, and for a remote Docker context. Everything that decides what can
run asks the daemon.
"""

import subprocess

# `uname -m` style names, as `docker info` reports them, to OCI platform names.
_ARCHITECTURES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm/v7",
    "i386": "386",
    "i686": "386",
}


def run(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str] | None:
    """Run a command; return None if it cannot start or does not finish in time."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def normalize_platform(os_type: str, architecture: str) -> str | None:
    arch = _ARCHITECTURES.get(architecture.strip().lower())
    os_name = os_type.strip().lower()
    if arch is None or not os_name:
        return None
    return f"{os_name}/{arch}"


def docker_platform() -> str | None:
    """The engine's platform, such as `linux/amd64`, or None if the daemon does not answer."""
    proc = run(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"])
    if proc is None or proc.returncode != 0 or "/" not in proc.stdout:
        return None
    os_type, architecture = proc.stdout.strip().split("/", 1)
    return normalize_platform(os_type, architecture)

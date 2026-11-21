"""Facts about the Docker Engine that Sosya talks to, read from the daemon itself.

Python's `platform.machine()` describes the interpreter, not the engine: it is wrong for an
x86_64 Python under Rosetta, and for a remote Docker context. Everything that decides what can
run asks the daemon.
"""

import re
import subprocess

MIN_ENGINE = (28, 0, 0)
"""The `isolated` gateway mode of internal bridge networks arrived in Docker Engine 28.0.0."""
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")

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


def parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION.match(text.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def version_problem(version: str) -> str | None:
    """Why this engine version cannot run Sosya's isolated networks, or None if it can."""
    parsed = parse_version(version)
    if parsed is None:
        return f"cannot read the Docker Engine version {version!r}"
    if parsed < MIN_ENGINE:
        minimum = ".".join(str(part) for part in MIN_ENGINE)
        return (
            f"Docker Engine {version} is too old: Sosya needs {minimum} or newer for "
            "isolated networks"
        )
    return None


def engine_problem() -> str | None:
    """Why the engine cannot run a range, or None when it is reachable and recent enough."""
    proc = run(["docker", "version", "--format", "{{.Server.Version}}"])
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return "the Docker daemon is not reachable: is Docker running for your user?"
    return version_problem(proc.stdout.strip())

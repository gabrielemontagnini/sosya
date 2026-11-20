"""Environment checks behind `sosya doctor`."""

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum

MIN_PYTHON = (3, 12)
LLM_ENV_VARS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL")


class Status(Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: Status
    detail: str


def _run(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str] | None:
    """Run a command; return None if it cannot start or does not finish in time."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _last_line(text: str) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()]
    return lines[-1] if lines else "no output"


def check_python() -> CheckResult:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] < MIN_PYTHON:
        return CheckResult("Python", Status.FAIL, f"{version}: Sosya needs 3.12 or newer")
    return CheckResult("Python", Status.OK, version)


def check_docker_cli() -> CheckResult:
    path = shutil.which("docker")
    if path is None:
        return CheckResult(
            "Docker CLI",
            Status.FAIL,
            "docker not found on PATH: install Docker Engine or Docker Desktop",
        )
    return CheckResult("Docker CLI", Status.OK, path)


def check_docker_daemon() -> CheckResult:
    if shutil.which("docker") is None:
        return CheckResult("Docker daemon", Status.FAIL, "skipped: docker CLI not found")
    proc = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if proc is None:
        return CheckResult("Docker daemon", Status.FAIL, "docker info did not answer in time")
    if proc.returncode != 0:
        return CheckResult(
            "Docker daemon",
            Status.FAIL,
            f"not reachable ({_last_line(proc.stderr)}): is Docker running for your user?",
        )
    return CheckResult("Docker daemon", Status.OK, f"server {proc.stdout.strip()}")


def check_compose() -> CheckResult:
    if shutil.which("docker") is None:
        return CheckResult("Docker Compose v2", Status.FAIL, "skipped: docker CLI not found")
    proc = _run(["docker", "compose", "version", "--short"])
    if proc is None or proc.returncode != 0:
        return CheckResult(
            "Docker Compose v2",
            Status.FAIL,
            "`docker compose` is missing: install the Compose v2 plugin",
        )
    return CheckResult("Docker Compose v2", Status.OK, proc.stdout.strip())


def check_architecture() -> CheckResult:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return CheckResult("CPU architecture", Status.OK, machine)
    if machine in {"arm64", "aarch64"}:
        return CheckResult(
            "CPU architecture",
            Status.WARN,
            f"{machine}: Vulhub images may be amd64-only and run slowly or break under emulation",
        )
    return CheckResult("CPU architecture", Status.WARN, f"{machine}: untested architecture")


def check_llm() -> CheckResult:
    configured = [name for name in LLM_ENV_VARS if os.environ.get(name)]
    if not configured:
        return CheckResult(
            "LLM provider",
            Status.WARN,
            "none configured: set ANTHROPIC_API_KEY, OPENAI_API_KEY or OPENAI_BASE_URL "
            "(e.g. Ollama). `sosya up` works without one.",
        )
    # Report which variables are set, never their values.
    return CheckResult("LLM provider", Status.OK, ", ".join(configured) + " set")


def run_checks() -> list[CheckResult]:
    return [
        check_python(),
        check_docker_cli(),
        check_docker_daemon(),
        check_compose(),
        check_architecture(),
        check_llm(),
    ]

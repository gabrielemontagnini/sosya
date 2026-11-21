"""`docker` and `docker compose` v2 through `subprocess`. No Docker SDK.

Every compose command passes `-p <project>` and `-f <file>`. The runner is injectable so unit
tests check the argv without a daemon.
"""

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sosya.render import LABEL_HOST, LABEL_RANGE, LABEL_ROLE

Runner = Callable[..., subprocess.CompletedProcess[str]]

LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
LABEL_CONFIG_FILES = "com.docker.compose.project.config_files"
LABEL_WORKING_DIR = "com.docker.compose.project.working_dir"


class DockerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContainerInfo:
    id: str
    project: str
    range: str
    host: str
    role: str
    service: str
    state: str
    health: str | None
    config_files: str
    working_dir: str
    exit_code: int = 0

    @classmethod
    def from_inspect(cls, data: dict[str, Any]) -> "ContainerInfo":
        labels = data.get("Config", {}).get("Labels") or {}
        state = data.get("State", {})
        health = state.get("Health")
        return cls(
            id=str(data.get("Id", ""))[:12],
            project=labels.get(LABEL_PROJECT, ""),
            range=labels.get(LABEL_RANGE, ""),
            host=labels.get(LABEL_HOST, ""),
            role=labels.get(LABEL_ROLE, ""),
            service=labels.get(LABEL_SERVICE, ""),
            state=str(state.get("Status", "unknown")),
            health=health.get("Status") if isinstance(health, dict) else None,
            config_files=labels.get(LABEL_CONFIG_FILES, ""),
            working_dir=labels.get(LABEL_WORKING_DIR, ""),
            exit_code=int(state.get("ExitCode") or 0),
        )


@dataclass(frozen=True)
class Docker:
    runner: Runner = subprocess.run

    def run(
        self, args: Sequence[str], *, capture: bool = True, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                ["docker", *args], capture_output=capture, text=True, check=False, timeout=timeout
            )
        except FileNotFoundError:
            raise DockerError("docker is not installed or not on PATH") from None
        except subprocess.TimeoutExpired:
            raise DockerError(f"docker {' '.join(args[:2])} did not finish in time") from None

    def compose(
        self, project: str, file: Path, *args: str, capture: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return self.run(["compose", "-p", project, "-f", str(file), *args], capture=capture)

    def copy_in(self, container: str, directory: str, archive: bytes) -> bool:
        """Extract a tar archive into a container's directory with `docker cp -` (no shell)."""
        try:
            proc = self.runner(
                ["docker", "cp", "-", f"{container}:{directory}"],
                input=archive,
                capture_output=True,
                check=False,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def copy_out(self, container: str, path: str) -> bytes | None:
        """A file from a container as a tar archive (`docker cp <id>:<path> -`), or None."""
        try:
            proc = self.runner(
                ["docker", "cp", f"{container}:{path}", "-"],
                capture_output=True,
                check=False,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0 or not isinstance(proc.stdout, bytes):
            return None
        return proc.stdout

    def image_exists(self, image: str) -> bool:
        return self.run(["image", "inspect", "--format", "{{.Id}}", image]).returncode == 0

    def pull(self, image: str, platform: str | None = None) -> subprocess.CompletedProcess[str]:
        args = ["pull", "--quiet"]
        if platform:
            args += ["--platform", platform]
        return self.run([*args, image])

    def build(self, tag: str, context: Path) -> subprocess.CompletedProcess[str]:
        return self.run(["build", "--tag", tag, str(context)])

    def containers(self, project: str | None = None) -> list[ContainerInfo]:
        """Every Sosya container, or those of one compose project, found by their labels."""
        args = ["ps", "--all", "--quiet", "--no-trunc", "--filter", f"label={LABEL_RANGE}"]
        if project is not None:
            args += ["--filter", f"label={LABEL_PROJECT}={project}"]
        proc = self.run(args)
        if proc.returncode != 0:
            raise DockerError(f"docker ps failed: {proc.stderr.strip()}")
        ids = proc.stdout.split()
        if not ids:
            return []
        proc = self.run(["inspect", *ids])
        if proc.returncode != 0:
            # A container can vanish between `ps` and `inspect`; inspect what is left.
            return [c for cid in ids for c in self._inspect_one(cid)]
        return [ContainerInfo.from_inspect(item) for item in json.loads(proc.stdout)]

    def _inspect_one(self, cid: str) -> list[ContainerInfo]:
        proc = self.run(["inspect", cid])
        if proc.returncode != 0:
            return []
        return [ContainerInfo.from_inspect(item) for item in json.loads(proc.stdout)]

    def project_networks(self, project: str) -> list[str]:
        args = ["network", "ls", "--quiet", "--filter", f"label={LABEL_PROJECT}={project}"]
        proc = self.run(args)
        return proc.stdout.split() if proc.returncode == 0 else []

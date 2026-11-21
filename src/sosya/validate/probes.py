"""Run many checks with few Docker calls, ported from the network spike.

All the checks that run in one network namespace go into one shell script, so a namespace costs
one `docker exec` (the attacker box) or one `docker run --network container:<id>` (a target,
probed with the attacker image, which is already present and has the tools; the target image
may have none). Each check prints one line, `<id> ok` or `<id> fail`.

A *reach* check must succeed and is retried until a deadline, inside the script, because a
service can be running before it listens. A *block* check must fail and runs once.
"""

import json
import shlex
import socket
from dataclasses import dataclass
from typing import Any, Literal

from sosya.runtime.docker import Docker

Kind = Literal["reach", "block"]
TCP_TIMEOUT = 3


@dataclass(frozen=True)
class Probe:
    id: str
    kind: Kind
    command: str


def tcp(host: str, port: int) -> str:
    """Connect without depending on nc flavours: bash's /dev/tcp, bounded by timeout."""
    target = f"/dev/tcp/{host}/{port}"
    return f"timeout {TCP_TIMEOUT} bash -c {shlex.quote(f'exec 3<>{target}')}"


def script(probes: list[Probe], ready_timeout: int) -> str:
    lines = [
        "reach() { id=$1; shift; end=$(( $(date +%s) + " + str(ready_timeout) + " ));",
        "  while :; do",
        '    if sh -c "$1" >/dev/null 2>&1; then echo "$id ok"; return; fi',
        '    if [ "$(date +%s)" -ge "$end" ]; then echo "$id fail"; return; fi',
        "    sleep 2",
        "  done; }",
        'block() { if sh -c "$2" >/dev/null 2>&1; then echo "$1 fail"; else echo "$1 ok"; fi; }',
    ]
    for probe in probes:
        lines.append(f"{probe.kind} {shlex.quote(probe.id)} {shlex.quote(probe.command)} &")
    lines.append("wait")
    return "\n".join(lines) + "\n"


def parse(output: str, probes: list[Probe]) -> dict[str, bool]:
    """Result of every probe; a probe whose line is missing failed."""
    seen: dict[str, bool] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("ok", "fail"):
            seen[parts[0]] = parts[1] == "ok"
    return {probe.id: seen.get(probe.id, False) for probe in probes}


def in_attacker(
    docker: Docker, container: str, probes: list[Probe], ready_timeout: int
) -> dict[str, bool]:
    if not probes:
        return {}
    proc = docker.run(
        ["exec", container, "sh", "-c", script(probes, ready_timeout)],
        timeout=ready_timeout + 60,
    )
    return parse(proc.stdout, probes)


def in_namespace(
    docker: Docker, container: str, image: str, probes: list[Probe], ready_timeout: int
) -> dict[str, bool]:
    if not probes:
        return {}
    proc = docker.run(
        [
            "run",
            "--rm",
            "--network",
            f"container:{container}",
            "--entrypoint",
            "sh",
            image,
            "-c",
            script(probes, ready_timeout),
        ],
        timeout=ready_timeout + 120,
    )
    return parse(proc.stdout, probes)


def inspect(docker: Docker, ids: list[str]) -> dict[str, dict[str, Any]]:
    """Raw `docker inspect` data by short id."""
    if not ids:
        return {}
    proc = docker.run(["inspect", *ids])
    if proc.returncode != 0:
        return {}
    return {str(item.get("Id", ""))[:12]: item for item in json.loads(proc.stdout)}


def addresses(data: dict[str, Any], project: str) -> dict[str, str]:
    """Network name (without the project prefix) → IPv4 address of the container."""
    networks = (data.get("NetworkSettings") or {}).get("Networks") or {}
    prefix = f"{project}_"
    return {
        name.removeprefix(prefix): str(item.get("IPAddress") or "")
        for name, item in networks.items()
        if item and item.get("IPAddress")
    }


def published(data: dict[str, Any]) -> list[str]:
    bindings = (data.get("HostConfig") or {}).get("PortBindings") or {}
    found = [port for port, value in bindings.items() if value]
    ports = (data.get("NetworkSettings") or {}).get("Ports") or {}
    found += [port for port, value in ports.items() if value and port not in found]
    return sorted(found)


def host_connects(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

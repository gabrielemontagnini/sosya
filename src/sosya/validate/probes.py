"""Run many checks with few Docker calls, ported from the network spike.

All the checks that run in one network namespace go into one shell script, so a namespace costs
one `docker exec` (the attacker box) or one `docker run --network container:<id>` (a target,
probed with the attacker image, which is already present and has the tools; the target image
may have none). Each check prints one line, `<id> ok` or `<id> fail`.

A *reach* check must succeed and is retried until a deadline, inside the script, because a
service can be running before it listens. A *block* check must fail and runs once. An
*optional* check is for a port the catalog marks optional (it may never listen): it waits,
within the same deadline, only for its `ready` command (the required ports of the same
service), then gets one short window of `OPTIONAL_GRACE` seconds instead of the whole deadline.
"""

import json
import shlex
import socket
from dataclasses import dataclass
from typing import Any, Literal

from sosya.runtime.docker import Docker

Kind = Literal["reach", "block", "optional"]
TCP_TIMEOUT = 3
OPTIONAL_GRACE = 5
"""Seconds an optional port gets once the required ports of its service answer."""


@dataclass(frozen=True)
class Probe:
    id: str
    kind: Kind
    command: str
    ready: str = ""
    """For an optional probe: what must succeed first (the service's required ports)."""


def tcp(host: str, port: int) -> str:
    """Connect without depending on nc flavours: bash's /dev/tcp, bounded by timeout."""
    target = f"/dev/tcp/{host}/{port}"
    return f"timeout {TCP_TIMEOUT} bash -c {shlex.quote(f'exec 3<>{target}')}"


def script(probes: list[Probe], ready_timeout: int, optional_grace: int = OPTIONAL_GRACE) -> str:
    lines = [
        "reach() { id=$1; shift; end=$(( $(date +%s) + " + str(ready_timeout) + " ));",
        "  while :; do",
        '    if sh -c "$1" >/dev/null 2>&1; then echo "$id ok"; return; fi',
        '    if [ "$(date +%s)" -ge "$end" ]; then echo "$id fail"; return; fi',
        "    sleep 2",
        "  done; }",
        'block() { if sh -c "$2" >/dev/null 2>&1; then echo "$1 fail"; else echo "$1 ok"; fi; }',
        "optional() { id=$1; end=$(( $(date +%s) + " + str(ready_timeout) + " ));",
        '  until sh -c "$2" >/dev/null 2>&1; do',
        '    if [ "$(date +%s)" -ge "$end" ]; then echo "$id fail"; return; fi',
        "    sleep 2",
        "  done",
        "  end=$(( $(date +%s) + " + str(optional_grace) + " ))",
        "  while :; do",
        '    if sh -c "$3" >/dev/null 2>&1; then echo "$id ok"; return; fi',
        '    if [ "$(date +%s)" -ge "$end" ]; then echo "$id fail"; return; fi',
        "    sleep 1",
        "  done; }",
    ]
    for probe in probes:
        if probe.kind == "optional":
            args = f"{shlex.quote(probe.ready)} {shlex.quote(probe.command)}"
        else:
            args = shlex.quote(probe.command)
        lines.append(f"{probe.kind} {shlex.quote(probe.id)} {args} &")
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


def bindings(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(container port, host IP, host port) of every published port of a container."""
    found = []
    for port, items in sorted(((data.get("HostConfig") or {}).get("PortBindings") or {}).items()):
        for item in items or []:
            found.append((port, str(item.get("HostIp") or ""), str(item.get("HostPort") or "")))
    return found


def host_addresses() -> list[str]:
    """This machine's own non-loopback addresses (IPv4 and IPv6), to check that nothing of a
    range answers on them. No packet is sent: a UDP socket only picks its source address."""
    found: list[str] = []
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 9))
                found.append(str(sock.getsockname()[0]))
        except OSError:
            pass
    try:
        for *_, address in socket.getaddrinfo(socket.gethostname(), None):
            found.append(str(address[0]))
    except OSError:
        pass
    usable = []
    for address in found:
        if address.startswith(("127.", "::1", "fe80:")) or address == "::":
            continue
        if address not in usable:
            usable.append(address)
    return usable


def forward_answers(port: int, host: str = "127.0.0.1", timeout: float = 2.0) -> bool:
    """A forward that reaches its service keeps the connection open, or sends a banner; one
    whose service does not answer is closed at once by the relay."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(1.5)
            try:
                return sock.recv(1) != b""
            except TimeoutError:
                return True  # open and waiting for the client to speak, as HTTP does
    except OSError:
        return False

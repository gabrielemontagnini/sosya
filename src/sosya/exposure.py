"""`sosya up --proxy` and `--expose`: what a range publishes on 127.0.0.1, and how.

Nothing of a range is ever published on another address, in IPv4 or IPv6. Targets never join a
network that is not internal, so both features go through two extra containers, both made from
the attacker image:

- `attacker-relay` runs in the attacker box's network namespace. It listens only on the box's
  address on the internal `relay` network, never on a segment: a SOCKS5 proxy (which therefore
  reaches only what the attacker box reaches, and gives no internet when the box has none) and
  one TCP forward per `--expose`.
- `relay` joins only `relay` and `proxy`, a plain bridge that is not internal, and is the only
  container with published ports (`127.0.0.1:<port>:<port>`). It forwards each port to
  `attacker-relay`. It joins no segment, so a target can neither reach it nor use it.

docs/architecture.md, "Proxy and expose", has the full model and the checks that
`sosya validate` runs on it.
"""

import contextlib
import socket
from dataclasses import dataclass
from typing import Any

from sosya import topology

RELAY = "relay"
FORWARDER = "attacker-relay"
LINK_ALIAS = "attacker-link"
"""The attacker box's DNS name on the `relay` network, where the forwarder listens."""
RELAY_NETWORK = "relay"
PUBLISH_NETWORK = "proxy"
LOCALHOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 1080
ROLE = "relay"
READY_FILE = "/tmp/sosya-ready"


class ExposureError(ValueError):
    pass


@dataclass(frozen=True)
class Forward:
    target: str
    """The rendered container key, such as `web` or `web-db`."""
    port: int
    local: int
    """The port on 127.0.0.1."""

    @property
    def label(self) -> str:
        return f"{self.target}:{self.port}"


@dataclass(frozen=True)
class Exposure:
    proxy_port: int | None = None
    forwards: tuple[Forward, ...] = ()

    @property
    def empty(self) -> bool:
        return self.proxy_port is None and not self.forwards

    @property
    def local_ports(self) -> list[int]:
        ports = [self.proxy_port] if self.proxy_port is not None else []
        return ports + [f.local for f in self.forwards]

    def state(self) -> dict[str, Any]:
        return {
            "proxy_port": self.proxy_port,
            "exposes": [f.__dict__ for f in self.forwards],
        }

    @classmethod
    def from_state(cls, proxy_port: int | None, exposes: list[dict[str, Any]]) -> "Exposure":
        forwards = tuple(
            Forward(str(f["target"]), int(f["port"]), int(f["local"])) for f in exposes
        )
        return cls(proxy_port, forwards)


def _port(text: str, what: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise ExposureError(f"{what} {text!r} is not a number") from None
    if not 1 <= port <= 65535:
        raise ExposureError(f"{what} {port} is not between 1 and 65535")
    return port


def parse_expose(text: str) -> Forward:
    """`web:8080` (on 127.0.0.1:8080) or `web:8080:18080` (on 127.0.0.1:18080)."""
    parts = text.strip().split(":")
    if len(parts) not in (2, 3) or not parts[0]:
        raise ExposureError(f"--expose {text!r}: use HOST:PORT or HOST:PORT:LOCAL_PORT")
    port = _port(parts[1], f"--expose {text!r}: port")
    local = _port(parts[2], f"--expose {text!r}: local port") if len(parts) == 3 else port
    return Forward(parts[0], port, local)


def problems(exposure: Exposure, plan: topology.Topology) -> list[str]:
    """Why the exposure cannot be built on this range's topology. Empty when it can."""
    found: list[str] = []
    if exposure.proxy_port is not None:
        _port(str(exposure.proxy_port), "--proxy-port")
    ports = exposure.local_ports
    duplicates = sorted({port for port in ports if ports.count(port) > 1})
    if duplicates:
        found.append(f"local port(s) used twice: {', '.join(map(str, duplicates))}")
    box = next(c for c in plan.containers if c.host == topology.ATTACKER)
    containers = {c.key: c for c in plan.containers if c.host != topology.ATTACKER}
    for forward in exposure.forwards:
        container = containers.get(forward.target)
        if container is None:
            names = ", ".join(sorted(containers))
            found.append(
                f"--expose {forward.label}: no service {forward.target} (there are {names})"
            )
        elif not set(container.segments) & set(box.segments):
            found.append(
                f"--expose {forward.label}: the attacker box does not reach {forward.target}, "
                "and --expose goes through the attacker box"
            )
    return found


def busy(ports: list[int], host: str = LOCALHOST) -> list[int]:
    """The ports among `ports` that something on this machine already listens on."""
    taken = []
    for port in ports:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.bind((host, port))
            except OSError:
                taken.append(port)
    return taken

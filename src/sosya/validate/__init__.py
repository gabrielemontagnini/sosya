"""Live checks on a running range: the same isolation checks CI runs, for every user's range.

1. services: every service is running (healthy, if it has a healthcheck), or ran once and
   exited with 0 (a one-shot such as `airflow-init`);
2. reach: the attacker box reaches every service it shares a network with, by name and by IP,
   on every TCP port the catalog lists;
3. segmentation: the attacker box neither resolves nor reaches containers it shares no network
   with;
4. targets have no internet: DNS, TCP over IPv4 and IPv6, HTTP and a default route all fail;
5. the host cannot reach the targets: no published port, no connection to their IPs;
6. the attacker box does not forward packets; its internet access is only a warning;
7. every flag is in place, with the value recorded at `up`;
8. callback: every target opens a TCP connection to the attacker box on each segment they
   share, as a reverse shell or a JNDI callback needs. A short-lived listener runs in the box
   for the duration of the checks, bound only to its segment addresses;
9. with `--proxy` or `--expose`: the relay publishes on 127.0.0.1 only (not on ::1 or the
   host's own addresses), the proxy reaches the services the attacker box reaches and, without
   internet, nothing else, every forward answers, and no target can use the proxy or the relay.

Checks are batched (one script per network namespace) and run in parallel across hosts.
"""

import json
import random
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sosya import attacker as attacker_image
from sosya import exposure as exposure_model
from sosya import topology
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex, Port
from sosya.exposure import Exposure
from sosya.render import project_name
from sosya.runtime import RangeError, Workspace
from sosya.runtime import state as state_store
from sosya.runtime.docker import ContainerInfo, Docker
from sosya.scenario import flags as flag_store
from sosya.spec import RangeSpec, SpecError, load_range
from sosya.validate import probes, socks
from sosya.validate.probes import Probe

READY_TIMEOUT = 90
CALLBACK_PORTS = (40000, 59999)
"""The listener for the callback checks takes a random port in this range, once per run."""
"""Seconds a service may take to start listening after its container runs."""
FALLBACK_PORT = 80

Level = Literal["check", "warning"]


@dataclass(frozen=True)
class Check:
    group: str
    target: str
    ok: bool
    detail: str = ""
    level: Level = "check"
    host: str = ""
    """The spec host the check is about, for logs in the repair loop ("" for the attacker)."""

    @property
    def failed(self) -> bool:
        return not self.ok and self.level == "check"


@dataclass(frozen=True)
class _Planned:
    probe: Probe
    group: str
    target: str
    host: str
    level: Level = "check"
    note: str = ""


def _tcp_port_info(
    index: CatalogIndex, spec: RangeSpec, container: topology.Container
) -> list[Port]:
    """The catalog's TCP ports of a container, sorted; optional ports included."""
    host = next((h for h in spec.hosts if h.name == container.host), None)
    entry = index.get(host.component) if host else None
    if entry is None:
        return []
    for service in entry.services:
        if service.name == container.original:
            found = {p.port: p for p in service.ports if p.protocol == "tcp"}
            return [found[port] for port in sorted(found)]
    return []


def _tcp_ports(index: CatalogIndex, spec: RangeSpec, container: topology.Container) -> list[int]:
    return [p.port for p in _tcp_port_info(index, spec, container)]


class _Range:
    def __init__(
        self,
        spec: RangeSpec,
        index: CatalogIndex,
        docker: Docker,
        services_of: Callable[[str], dict[str, Any]],
    ) -> None:
        self.spec = spec
        self.index = index
        self.docker = docker
        self.project = project_name(spec.name)
        self.plan = topology.build(spec, services_of)
        self.found: dict[str, ContainerInfo] = {
            c.service: c for c in docker.containers(self.project)
        }
        self.data = probes.inspect(docker, [c.id for c in self.found.values()])

    def info(self, key: str) -> ContainerInfo | None:
        return self.found.get(key)

    def ips(self, key: str) -> dict[str, str]:
        info = self.info(key)
        return probes.addresses(self.data.get(info.id, {}), self.project) if info else {}

    def targets(self) -> list[topology.Container]:
        return [c for c in self.plan.containers if c.host != topology.ATTACKER]

    def attacker(self) -> topology.Container:
        return next(c for c in self.plan.containers if c.host == topology.ATTACKER)


def _service_checks(lab: _Range) -> list[Check]:
    checks = []
    for container in lab.plan.containers:
        info = lab.info(container.key)
        if info is None:
            checks.append(
                Check("service", container.key, False, "not created", host=container.host)
            )
            continue
        if info.state == "exited" and info.exit_code == 0:
            checks.append(
                Check("service", container.key, True, "ran once, exited 0", host=container.host)
            )
        elif info.state == "running" and info.health in (None, "healthy"):
            detail = "running" + (", healthy" if info.health else "")
            checks.append(Check("service", container.key, True, detail, host=container.host))
        else:
            detail = info.state + (f" ({info.exit_code})" if info.state == "exited" else "")
            if info.health:
                detail += f", {info.health}"
            checks.append(Check("service", container.key, False, detail, host=container.host))
    return checks


def _attacker_probes(lab: _Range) -> list[_Planned]:
    box = lab.attacker()
    shared = set(box.segments)
    planned: list[_Planned] = []
    counter = 0

    def add(
        kind: probes.Kind,
        command: str,
        group: str,
        target: str,
        host: str,
        level: Level = "check",
        note: str = "",
        ready: str = "",
    ) -> None:
        nonlocal counter
        counter += 1
        probe = Probe(f"a{counter}", kind, command, ready)
        planned.append(_Planned(probe, group, target, host, level, note))

    for container in lab.targets():
        info = lab.info(container.key)
        if info is None or info.state != "running":
            continue
        port_info = _tcp_port_info(lab.index, lab.spec, container)
        ports = [p.port for p in port_info]
        common = shared & set(container.networks)
        if common:
            if not container.segments:
                continue
            required = [p.port for p in port_info if not p.optional]
            addresses = [(container.key, f"{container.key}:")]
            for network in sorted(common):
                ip = lab.ips(container.key).get(network)
                if ip:
                    addresses.append((ip, f"{container.key} {ip}:"))
            for info in port_info:
                port = info.port
                # An optional port that never listens is an upstream quirk, not a broken range:
                # it only warns, and waits for the required ports of its service rather than
                # the whole deadline. With no required port it keeps the normal deadline.
                level: Level = "warning" if info.optional else "check"
                for address, label in addresses:
                    ready = " && ".join(probes.tcp(address, p) for p in required)
                    kind: probes.Kind = "optional" if info.optional and ready else "reach"
                    add(
                        kind,
                        probes.tcp(address, port),
                        "reach",
                        f"{label}{port}",
                        container.host,
                        level,
                        info.reason,
                        ready if kind == "optional" else "",
                    )
            if not ports:
                add(
                    "reach",
                    f"getent hosts {container.key}",
                    "reach",
                    f"{container.key} (dns)",
                    container.host,
                )
        else:
            add(
                "block",
                f"getent hosts {container.key}",
                "segmentation",
                f"{container.key} (dns)",
                container.host,
            )
            for network, ip in sorted(lab.ips(container.key).items()):
                for port in ports or [FALLBACK_PORT]:
                    add(
                        "block",
                        probes.tcp(ip, port),
                        "segmentation",
                        f"{container.key} {ip}:{port} ({network})",
                        container.host,
                    )
    add(
        "reach",
        '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ]',
        "attacker",
        "no packet forwarding",
        "",
    )
    if lab.spec.attacker.internet:
        add(
            "reach",
            "getent hosts example.com && curl -sfI -m 10 https://example.com",
            "attacker",
            "internet access",
            "",
            level="warning",
        )
    return planned


NO_INTERNET = (
    ("dns", "getent hosts example.com"),
    ("tcp", probes.tcp("1.1.1.1", 443)),
    ("tcp6", "nc -6 -z -w 3 2606:4700::1111 443"),
    ("http", "curl -s -m 3 -o /dev/null http://example.com"),
    ("default route", "ip route | grep -q ^default"),
)


def _callbacks(lab: "_Range", container: topology.Container) -> list[tuple[str, str]]:
    """(segment, attacker box address) of every segment the container shares with the box."""
    box = lab.ips(topology.ATTACKER)
    shared = set(container.segments) & set(lab.attacker().segments)
    return [(network, box[network]) for network in sorted(shared) if network in box]


def _namespace_probes(
    container: topology.Container,
    relay_targets: list[tuple[str, str, int]] = (),
    callbacks: list[tuple[str, str]] = (),
    callback_port: int = 0,
) -> list[_Planned]:
    planned = [
        _Planned(
            Probe(f"n{i}", "block", command),
            "no internet",
            f"{container.key} ({name})",
            container.host,
        )
        for i, (name, command) in enumerate(NO_INTERNET)
    ]
    # The proxy and the relay must be unusable from a target: nothing answers on them.
    for i, (what, address, port) in enumerate(relay_targets):
        planned.append(
            _Planned(
                Probe(f"n{len(NO_INTERNET) + i}", "block", probes.tcp(address, port)),
                "exposure",
                f"{container.key} → {what} {address}:{port}",
                container.host,
            )
        )
    # A reverse shell or a JNDI callback needs the target to connect back to the attacker box.
    start = len(planned)
    for i, (network, address) in enumerate(callbacks):
        planned.append(
            _Planned(
                Probe(f"n{start + i}", "reach", probes.tcp(address, callback_port)),
                "callback",
                f"{container.key} → attacker ({network})",
                container.host,
            )
        )
    return planned


def _relay_targets(lab: "_Range", exposure: Exposure) -> list[tuple[str, str, int]]:
    """Every address of the attacker box and the relay, with every relay port."""
    if exposure.empty:
        return []
    addresses: list[tuple[str, str]] = [
        ("relay", exposure_model.RELAY),
        ("attacker", exposure_model.LINK_ALIAS),
    ]
    for key, what in ((topology.ATTACKER, "attacker"), (exposure_model.RELAY, "relay")):
        addresses += [(what, ip) for ip in sorted(lab.ips(key).values())]
    return [(what, address, port) for what, address in addresses for port in exposure.local_ports]


def _results(planned: list[_Planned], results: dict[str, bool]) -> list[Check]:
    checks = []
    for item in planned:
        ok = results.get(item.probe.id, False)
        if item.group == "segmentation":
            detail = "blocked" if ok else "reachable from the attacker box"
        elif item.group == "no internet":
            detail = "blocked" if ok else "the target reaches the internet"
        elif item.group == "exposure":
            detail = "blocked" if ok else "the target can use the relay"
        elif item.group == "callback":
            detail = "connected" if ok else f"no connection within {READY_TIMEOUT}s"
        elif item.group == "reach":
            detail = "reachable" if ok else f"no answer within {READY_TIMEOUT}s"
            if not ok and item.probe.kind == "optional":
                detail = f"no answer within {probes.OPTIONAL_GRACE}s of its service"
            if not ok and item.level == "warning":
                detail += f" (optional port: {item.note})"
        else:
            detail = "ok" if ok else "failed"
        checks.append(Check(item.group, item.target, ok, detail, item.level, item.host))
    return checks


def _host_checks(lab: _Range, container: topology.Container) -> list[Check]:
    info = lab.info(container.key)
    if info is None:
        return []
    checks = []
    bound = probes.published(lab.data.get(info.id, {}))
    checks.append(
        Check(
            "host isolation",
            f"{container.key} ports",
            not bound,
            "none published" if not bound else "published: " + ", ".join(bound),
            host=container.host,
        )
    )
    if info.state == "running":
        ports = _tcp_ports(lab.index, lab.spec, container) or [FALLBACK_PORT]
        for network, ip in sorted(lab.ips(container.key).items()):
            for port in ports:
                reached = probes.host_connects(ip, port)
                checks.append(
                    Check(
                        "host isolation",
                        f"{container.key} {ip}:{port} ({network})",
                        not reached,
                        "blocked" if not reached else "reachable from the host",
                        host=container.host,
                    )
                )
    return checks


def _flag_checks(lab: _Range, record: state_store.RangeState) -> list[Check]:
    checks = []
    for host in lab.spec.hosts:
        flag = record.flags.get(host.name)
        info = lab.info(host.name)
        if flag is None:
            checks.append(Check("flag", host.name, False, "no flag was placed", host=host.name))
            continue
        value = flag_store.read(lab.docker, info.id, flag["path"]) if info else None
        ok = value == flag["value"]
        detail = flag["path"] if ok else f"{flag['path']} missing or changed"
        checks.append(Check("flag", host.name, ok, detail, host=host.name))
    return checks


def _until(deadline: float, attempt: Callable[[], bool]) -> bool:
    while True:
        if attempt():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def _exposure_checks(lab: _Range, exposure: Exposure, ready_timeout: int) -> list[Check]:
    """What `--proxy` and `--expose` publish: on 127.0.0.1 only, and working."""
    checks: list[Check] = []

    def add(target: str, ok: bool, good: str, bad: str, level: Level = "check") -> None:
        checks.append(Check("exposure", target, ok, good if ok else bad, level))

    for key in (exposure_model.FORWARDER, exposure_model.RELAY):
        info = lab.info(key)
        ok = info is not None and info.state == "running" and info.health in (None, "healthy")
        state = "not created" if info is None else f"{info.state}, {info.health or 'no health'}"
        add(key, ok, "running, healthy", state)

    expected = {
        (f"{port}/tcp", exposure_model.LOCALHOST, str(port)) for port in exposure.local_ports
    }
    for key, info in sorted(lab.found.items()):
        bound = set(probes.bindings(lab.data.get(info.id, {})))
        if key == exposure_model.RELAY:
            wrong = sorted(b for b in bound if b[1] != exposure_model.LOCALHOST)
            ok = bound == expected and not wrong
            shown = ", ".join(f"{ip or '*'}:{host_port}" for _, ip, host_port in sorted(bound))
            add(
                "relay ports", ok, f"127.0.0.1 only ({shown})", f"published on {shown or 'nothing'}"
            )
        elif key in (topology.ATTACKER, exposure_model.FORWARDER) and bound:
            add(f"{key} ports", False, "", "published: " + ", ".join(b[0] for b in sorted(bound)))

    deadline = time.monotonic() + ready_timeout
    others = probes.host_addresses()
    for port in exposure.local_ports:
        ok = _until(deadline, lambda port=port: probes.host_connects("127.0.0.1", port))
        add(f"127.0.0.1:{port}", ok, "answers", "no answer")
        for address in ["::1", *others]:
            reached = probes.host_connects(address, port)
            shown = f"[{address}]" if ":" in address else address
            add(f"{shown}:{port}", not reached, "refused", "answers: published beyond 127.0.0.1")

    if exposure.proxy_port is not None:
        proxy = ("127.0.0.1", exposure.proxy_port)
        box = lab.attacker()
        for container in lab.targets():
            info = lab.info(container.key)
            if info is None or info.state != "running":
                continue
            if not set(container.segments) & set(box.segments):
                continue
            port_infos = _tcp_port_info(lab.index, lab.spec, container)
            has_required = any(not p.optional for p in port_infos)
            # Required ports first, with the deadline; then each optional port gets a short
            # window (the whole deadline only when the service has no required port).
            for port_info in sorted(port_infos, key=lambda p: (p.optional, p.port)):
                until = deadline
                if port_info.optional and has_required:
                    until = min(deadline, time.monotonic() + probes.OPTIONAL_GRACE)
                ok = _until(
                    until,
                    lambda c=container, p=port_info.port: socks.connect(proxy, c.key, p),
                )
                level: Level = "warning" if port_info.optional else "check"
                add(
                    f"proxy → {container.key}:{port_info.port}", ok, "reachable", "no answer", level
                )
        if not lab.spec.attacker.internet:
            for host, port in (("1.1.1.1", 443), ("example.com", 443)):
                reached = socks.connect(proxy, host, port)
                add(
                    f"proxy → {host}:{port}",
                    not reached,
                    "blocked",
                    "the proxy reaches the internet",
                )

    for forward in exposure.forwards:
        ok = _until(deadline, lambda f=forward: probes.forward_answers(f.local))
        add(f"127.0.0.1:{forward.local} → {forward.label}", ok, "forwarded", "no answer")
    return checks


GROUP_ORDER = (
    "service",
    "reach",
    "callback",
    "segmentation",
    "no internet",
    "host isolation",
    "exposure",
    "attacker",
    "flag",
)


def validate(
    name: str,
    *,
    workspace: Workspace | None = None,
    docker: Docker | None = None,
    index: CatalogIndex | None = None,
    services_of: Callable[[str], dict[str, Any]] = load_services,
    ready_timeout: int = READY_TIMEOUT,
) -> list[Check]:
    """Every check on the running range `name`. Raise `RangeError` if it is not running here."""
    workspace = workspace or Workspace()
    docker = docker or Docker()
    record = state_store.load(workspace.root).get(name)
    if record is None:
        raise RangeError(f"no range named {name} was started from this directory")
    try:
        spec = load_range(Path(record.source))
    except SpecError as exc:
        raise RangeError(str(exc)) from None
    lab = _Range(spec, index or load_index(), docker, services_of)
    if not lab.found:
        raise RangeError(f"range {name} is not running: start it with `sosya up {name}`")
    image = attacker_image.image()
    exposure = Exposure.from_state(record.proxy_port, record.exposes)
    relay_targets = _relay_targets(lab, exposure)

    box = lab.info(topology.ATTACKER)
    attacker_planned = _attacker_probes(lab) if box and box.state == "running" else []
    namespaces = [
        c
        for c in lab.targets()
        if c.shares_network_of is None and (i := lab.info(c.key)) and i.state == "running"
    ]
    callbacks = {
        c.key: _callbacks(lab, c) if box and box.state == "running" else [] for c in namespaces
    }
    port = _callback_port(exposure)
    listening = _listen(docker, box.id, callbacks, port, ready_timeout) if box else []
    try:
        checks = _run_checks(
            lab,
            docker,
            box,
            attacker_planned,
            namespaces,
            image,
            relay_targets,
            record,
            exposure,
            ready_timeout,
            callbacks,
            port,
        )
    finally:
        if listening and box:
            docker.run(["exec", box.id, "pkill", "-f", f"TCP-LISTEN:{port},"])
    order = {group: i for i, group in enumerate(GROUP_ORDER)}
    return sorted(checks, key=lambda c: (order.get(c.group, 99), c.target))


def _callback_port(exposure: Exposure) -> int:
    while True:
        port = random.randint(*CALLBACK_PORTS)
        if port not in exposure.local_ports:
            return port


def _listen(
    docker: Docker,
    box: str,
    callbacks: dict[str, list[tuple[str, str]]],
    port: int,
    ready_timeout: int,
) -> list[str]:
    """Start one listener per attacker box address that a target must call back to."""
    addresses = sorted({address for pairs in callbacks.values() for _, address in pairs})
    for address in addresses:
        docker.run(
            [
                "exec",
                "-d",
                box,
                "timeout",
                str(ready_timeout + 120),
                "socat",
                f"TCP-LISTEN:{port},bind={address},fork,reuseaddr",
                "EXEC:true",
            ]
        )
    return addresses


def _run_checks(
    lab: "_Range",
    docker: Docker,
    box: ContainerInfo | None,
    attacker_planned: list[_Planned],
    namespaces: list[topology.Container],
    image: str,
    relay_targets: list[tuple[str, str, int]],
    record: state_store.RangeState,
    exposure: Exposure,
    ready_timeout: int,
    callbacks: dict[str, list[tuple[str, str]]],
    port: int,
) -> list[Check]:
    def planned_for(container: topology.Container) -> list[_Planned]:
        return _namespace_probes(container, relay_targets, callbacks[container.key], port)

    with ThreadPoolExecutor(max_workers=8) as pool:
        attacker_future = pool.submit(
            probes.in_attacker,
            docker,
            box.id if box else "",
            [p.probe for p in attacker_planned],
            ready_timeout,
        )
        namespace_futures = {
            c.key: pool.submit(
                probes.in_namespace,
                docker,
                lab.info(c.key).id,
                image,  # type: ignore[union-attr]
                [p.probe for p in planned_for(c)],
                ready_timeout,
            )
            for c in namespaces
        }
        host_futures = [pool.submit(_host_checks, lab, c) for c in lab.targets()]
        flag_future = pool.submit(_flag_checks, lab, record)
        exposure_future = (
            pool.submit(_exposure_checks, lab, exposure, ready_timeout)
            if not exposure.empty
            else None
        )

        checks = _service_checks(lab)
        if box is None or box.state != "running":
            checks.append(Check("attacker", "attacker box", False, "not running"))
        checks += _results(attacker_planned, attacker_future.result())
        for container in namespaces:
            checks += _results(planned_for(container), namespace_futures[container.key].result())
        for future in host_futures:
            checks += future.result()
        checks += flag_future.result()
        if exposure_future is not None:
            checks += exposure_future.result()
    return checks


def failures(checks: list[Check]) -> list[Check]:
    return [check for check in checks if check.failed]


def to_json(checks: list[Check]) -> str:
    return json.dumps([check.__dict__ for check in checks], indent=2)

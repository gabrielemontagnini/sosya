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
7. every flag is in place, with the value recorded at `up`.

Checks are batched (one script per network namespace) and run in parallel across hosts.
"""

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from sosya import attacker as attacker_image
from sosya import topology
from sosya.catalog.loader import load_index, load_services
from sosya.catalog.models import CatalogIndex, Port
from sosya.render import project_name
from sosya.runtime import RangeError, Workspace
from sosya.runtime import state as state_store
from sosya.runtime.docker import ContainerInfo, Docker
from sosya.scenario import flags as flag_store
from sosya.spec import RangeSpec, SpecError, load_range
from sosya.validate import probes
from sosya.validate.probes import Probe

READY_TIMEOUT = 90
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
    ) -> None:
        nonlocal counter
        counter += 1
        probe = Probe(f"a{counter}", kind, command)
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
            for info in port_info:
                port = info.port
                # An optional port that never listens is an upstream quirk, not a broken range.
                level: Level = "warning" if info.optional else "check"
                add(
                    "reach",
                    probes.tcp(container.key, port),
                    "reach",
                    f"{container.key}:{port}",
                    container.host,
                    level,
                    info.reason,
                )
                for network in sorted(common):
                    ip = lab.ips(container.key).get(network)
                    if ip:
                        add(
                            "reach",
                            probes.tcp(ip, port),
                            "reach",
                            f"{container.key} {ip}:{port}",
                            container.host,
                            level,
                            info.reason,
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


def _namespace_probes(container: topology.Container) -> list[_Planned]:
    return [
        _Planned(
            Probe(f"n{i}", "block", command),
            "no internet",
            f"{container.key} ({name})",
            container.host,
        )
        for i, (name, command) in enumerate(NO_INTERNET)
    ]


def _results(planned: list[_Planned], results: dict[str, bool]) -> list[Check]:
    checks = []
    for item in planned:
        ok = results.get(item.probe.id, False)
        if item.group == "segmentation":
            detail = "blocked" if ok else "reachable from the attacker box"
        elif item.group == "no internet":
            detail = "blocked" if ok else "the target reaches the internet"
        elif item.group == "reach":
            detail = "reachable" if ok else f"no answer within {READY_TIMEOUT}s"
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


GROUP_ORDER = (
    "service",
    "reach",
    "segmentation",
    "no internet",
    "host isolation",
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

    box = lab.info(topology.ATTACKER)
    attacker_planned = _attacker_probes(lab) if box and box.state == "running" else []
    namespaces = [
        c
        for c in lab.targets()
        if c.shares_network_of is None and (i := lab.info(c.key)) and i.state == "running"
    ]
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
                [p.probe for p in _namespace_probes(c)],
                ready_timeout,
            )
            for c in namespaces
        }
        host_futures = [pool.submit(_host_checks, lab, c) for c in lab.targets()]
        flag_future = pool.submit(_flag_checks, lab, record)

        checks = _service_checks(lab)
        if box is None or box.state != "running":
            checks.append(Check("attacker", "attacker box", False, "not running"))
        checks += _results(attacker_planned, attacker_future.result())
        for container in namespaces:
            checks += _results(
                _namespace_probes(container), namespace_futures[container.key].result()
            )
        for future in host_futures:
            checks += future.result()
        checks += flag_future.result()
    order = {group: i for i, group in enumerate(GROUP_ORDER)}
    return sorted(checks, key=lambda c: (order.get(c.group, 99), c.target))


def failures(checks: list[Check]) -> list[Check]:
    return [check for check in checks if check.failed]


def to_json(checks: list[Check]) -> str:
    return json.dumps([check.__dict__ for check in checks], indent=2)

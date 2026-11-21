"""The containers and networks a range turns into, and the names they get.

`spec.check_catalog` and the renderer both build the topology here, so the plan the user
approves and the compose file that runs use the same names, and a clash found by one is found
by the other.
"""

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sosya.spec import Host, RangeSpec

ATTACKER = "attacker"
EGRESS = "egress"
PRIVATE_SUFFIX = "-net"

ServicesOf = Callable[[str], Mapping[str, Mapping[str, Any]]]


@dataclass(frozen=True)
class Container:
    key: str
    """The rendered service name, which is also its DNS name on every network it joins."""
    host: str
    """The spec host it belongs to, or `attacker`."""
    original: str
    """The Vulhub service name (empty for the attacker box)."""
    primary: bool
    segments: tuple[str, ...]
    """Scenario networks it joins: only services that Vulhub publishes, and the attacker box."""
    private: str | None = None
    """The component's private network, for components with two or more services."""
    private_aliases: tuple[str, ...] = ()
    """Its Vulhub names on the private network: the service name and any `links` alias."""
    shares_network_of: str | None = None
    """For `network_mode: service:<sibling>`: the sibling's rendered key."""

    @property
    def networks(self) -> tuple[str, ...]:
        return self.segments + ((self.private,) if self.private else ())


@dataclass(frozen=True)
class Topology:
    containers: tuple[Container, ...]
    segments: tuple[str, ...]
    private_networks: tuple[str, ...]
    egress: bool

    def of_host(self, host: str) -> list[Container]:
        return [c for c in self.containers if c.host == host]

    def key_map(self, host: str) -> dict[str, str]:
        """Vulhub service name → rendered key, for one host."""
        return {c.original: c.key for c in self.of_host(host)}


def primary_service(host: "Host", services: Mapping[str, Mapping[str, Any]]) -> str:
    """The service that takes the host's DNS name: `service:`, else the first with `ports`."""
    if host.service is not None:
        return host.service
    for name, definition in services.items():
        if "ports" in definition:
            return name
    return next(iter(services))


def _link_aliases(services: Mapping[str, Mapping[str, Any]]) -> dict[str, list[str]]:
    """`links: [db:mysql]` → {"db": ["mysql"]}: the alias the linking service uses."""
    aliases: dict[str, list[str]] = defaultdict(list)
    for definition in services.values():
        for link in definition.get("links", []):
            target, _, alias = str(link).partition(":")
            if alias and alias != target and alias not in aliases[target]:
                aliases[target].append(alias)
    return aliases


def build(spec: "RangeSpec", services_of: ServicesOf) -> Topology:
    """Plan every container. The components and `service:` names must already be valid."""
    containers: list[Container] = []
    private_networks: list[str] = []
    for host in spec.hosts:
        services = services_of(host.component)
        primary = primary_service(host, services)
        private = f"{host.name}{PRIVATE_SUFFIX}" if len(services) >= 2 else None
        if private:
            private_networks.append(private)
        links = _link_aliases(services)
        keys = {name: host.name if name == primary else f"{host.name}-{name}" for name in services}
        for name, definition in services.items():
            mode = str(definition.get("network_mode", ""))
            sibling = mode.removeprefix("service:") if mode.startswith("service:") else None
            exposed = name == primary or "ports" in definition
            containers.append(
                Container(
                    key=keys[name],
                    host=host.name,
                    original=name,
                    primary=name == primary,
                    segments=tuple(host.networks) if exposed and sibling is None else (),
                    private=private if sibling is None else None,
                    private_aliases=(name, *links.get(name, [])) if private else (),
                    shares_network_of=keys.get(sibling) if sibling else None,
                )
            )
    networks = list(spec.attacker.networks)
    if spec.attacker.internet:
        networks.append(EGRESS)
    containers.append(
        Container(key=ATTACKER, host=ATTACKER, original="", primary=True, segments=tuple(networks))
    )
    return Topology(
        containers=tuple(containers),
        segments=tuple(spec.networks),
        private_networks=tuple(private_networks),
        egress=spec.attacker.internet,
    )


def name_problems(topology: Topology) -> list[tuple[str, str]]:
    """Clashing or ambiguous names, as (host, message). Empty when every name is unique."""
    problems: list[tuple[str, str]] = []
    owners: dict[str, list[Container]] = defaultdict(list)
    for container in topology.containers:
        owners[container.key].append(container)
    for key, same in owners.items():
        if len(same) > 1:
            hosts = ", ".join(sorted({c.host for c in same}))
            problems.append((same[1].host, f"service name {key!r} is generated twice ({hosts})"))

    network_names = [
        *topology.segments,
        *topology.private_networks,
        *([EGRESS] if topology.egress else []),
    ]
    seen: set[str] = set()
    for name in network_names:
        if name in seen:
            problems.append(("", f"network name {name!r} is generated twice"))
        seen.add(name)

    # Name → containers it resolves to, network by network.
    resolves: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for container in topology.containers:
        for network in container.networks:
            resolves[network][container.key].add(container.key)
            if network == container.private:
                for alias in container.private_aliases:
                    resolves[network][alias].add(container.key)
    reported: set[tuple[str, frozenset[str]]] = set()
    for container in topology.containers:
        merged: dict[str, set[str]] = defaultdict(set)
        where: dict[tuple[str, str], list[str]] = defaultdict(list)
        for network in container.networks:
            for name, keys in resolves[network].items():
                merged[name] |= keys
                for key in keys:
                    where[(name, key)].append(network)
        for name, keys in sorted(merged.items()):
            if len(keys) < 2 or (name, frozenset(keys)) in reported:
                continue
            reported.add((name, frozenset(keys)))
            meanings = "; ".join(
                f"{key} on {', '.join(where[(name, key)])}" for key in sorted(keys)
            )
            problems.append(
                (
                    container.host,
                    f"DNS name {name!r} is ambiguous for {container.key}: it means {meanings}. "
                    "Rename the host.",
                )
            )
    return problems

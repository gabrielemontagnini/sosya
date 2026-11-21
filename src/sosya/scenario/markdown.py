"""SCENARIO.md, generated from the range and the catalog alone: no LLM, same input, same text.

It shows where the flags are, never their values. Hints are progressive and hidden in closed
`<details>` blocks, three per host: what runs there (product and ports), the class of the
vulnerability (catalog tags, no CVE), then the spoiler (title, CVEs, the Vulhub page and the
references). A host the attacker box cannot reach directly gets one more: the hosts to go
through.
"""

from collections.abc import Callable, Mapping
from typing import Any

from sosya import topology
from sosya.catalog.loader import load_services
from sosya.catalog.models import CatalogIndex, Entry
from sosya.spec import RangeSpec

VULHUB_TREE = "https://github.com/vulhub/vulhub/tree/{commit}/{path}"
CVE_LINK = "https://nvd.nist.gov/vuln/detail/{cve}"


def _ports(index: CatalogIndex, component: str, service: str) -> str:
    entry = index.get(component)
    if entry is None:
        return ""
    for item in entry.services:
        if item.name == service:
            return ", ".join(f"{p.port}/{p.protocol}" for p in item.ports)
    return ""


CATEGORY_TAGS = ("Framework", "Webserver", "Database", "CMS", "Message Queue", "LLM", "Other")
"""Catalog tags that say what a product is, not what is wrong with it."""
CLASS_NAMES = {
    "RCE": "remote code execution",
    "Auth Bypass": "authentication bypass",
    "Info Disclosure": "information disclosure",
    "Hard Coding": "hard-coded credentials or secrets",
    "Path Traversal": "path traversal or arbitrary file read",
}
NO_CLASS = "The catalog gives no class for this one: the next hint names it."


def product_hint(entry: Entry, services: list[str]) -> str:
    """Hint 1: the product, its kind and the services it publishes. Never the title or a CVE."""
    kinds = [tag for tag in entry.tags if tag in CATEGORY_TAGS and tag != "Other"]
    text = entry.product + (f" ({', '.join(kinds)})" if kinds else "") + "."
    if services:
        text += f" Listening: {'; '.join(services)}."
    return text


def class_hint(entry: Entry) -> str:
    """Hint 2: the vulnerability class, from the catalog tags. Never a CVE."""
    classes = [CLASS_NAMES.get(tag, tag) for tag in entry.tags if tag not in CATEGORY_TAGS]
    if not classes:
        return NO_CLASS
    return "The vulnerability class: " + ", ".join(classes) + "."


def route_hint(hops: list[topology.Hop] | None) -> str:
    if hops is None:
        return "No path from the attacker box reaches this host."
    steps = "; then ".join(f"{hop.host}, which also joins {hop.into}" for hop in hops)
    return f"The attacker box does not reach this host directly. Pivot through {steps}."


def _details(summary: str, body: list[str]) -> list[str]:
    return [f"<details><summary>{summary}</summary>", "", *body, "", "</details>", ""]


def render(
    spec: RangeSpec,
    index: CatalogIndex,
    flag_paths: Mapping[str, str],
    *,
    services_of: Callable[[str], Mapping[str, Mapping[str, Any]]] = load_services,
) -> str:
    plan = topology.build(spec, services_of)
    lines = [f"# {spec.name}", ""]
    if spec.description:
        lines += [spec.description, ""]
    lines += [f"Start with `sosya shell {spec.name}`: a Kali box inside the range.", ""]

    lines += ["## Objectives", ""]
    if spec.objectives:
        lines += [f"{i}. {objective}" for i, objective in enumerate(spec.objectives, start=1)]
    else:
        lines.append("1. Capture the flag on every host.")
    lines.append("")

    lines += ["## Network map", "", "| Network | Hosts |", "| --- | --- |"]
    for network in spec.networks:
        members = [topology.ATTACKER] if network in spec.attacker.networks else []
        members += [h.name for h in spec.hosts if network in h.networks]
        lines.append(f"| {network} | {', '.join(members)} |")
    internet = "has internet access" if spec.attacker.internet else "has no internet access"
    lines += [
        "",
        f"The attacker box joins {', '.join(spec.attacker.networks)} and {internet}. Targets "
        "have no internet access. A host on two networks is the only way from one to the other.",
        "",
    ]

    lines += ["## Hosts", "", "| Host | Networks | Services | Flag |", "| --- | --- | --- | --- |"]
    published: dict[str, list[str]] = {}
    for host in spec.hosts:
        services = []
        for container in plan.of_host(host.name):
            if not container.segments:
                continue
            ports = _ports(index, host.component, container.original)
            services.append(f"{container.key} ({ports})" if ports else container.key)
        published[host.name] = services
        path = flag_paths.get(host.name)
        flag = f"`{path}`" if path else "not placed"
        lines.append(
            f"| {host.name} | {', '.join(host.networks)} | {'; '.join(services)} | {flag} |"
        )
    lines += ["", "Flags look like `SOSYA{...}` and change every time the range starts.", ""]

    lines += ["## Hints", "", "Open them one at a time, only when you are stuck.", ""]
    routes = topology.routes(spec)
    for host in spec.hosts:
        entry = index.get(host.component)
        lines += [f"### {host.name}", ""]
        if host.name in routes:
            lines += _details("The way in", [route_hint(routes[host.name])])
        if entry is None:
            lines += [f"`{host.component}`", ""]
            continue
        lines += _details("Hint 1: what runs here", [product_hint(entry, published[host.name])])
        lines += _details("Hint 2: the kind of vulnerability", [class_hint(entry)])
        spoiler = [entry.title, ""]
        spoiler += [f"- [{cve}]({CVE_LINK.format(cve=cve)})" for cve in entry.cves]
        url = VULHUB_TREE.format(commit=index.vulhub_commit, path=entry.path)
        spoiler.append(f"- Vulhub environment: [{entry.path}]({url})")
        spoiler += [f"- {reference}" for reference in entry.references]
        lines += _details("Hint 3: the spoiler", spoiler)
    lines += [
        "---",
        "",
        "Generated by Sosya from range.yaml and the Vulhub catalog "
        f"(commit `{index.vulhub_commit[:7]}`).",
        "",
    ]
    return "\n".join(lines)

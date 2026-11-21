"""Rich rendering of catalog search results for `sosya catalog`."""

import json
import platform
from collections.abc import Sequence

from rich.table import Table
from rich.text import Text

from sosya import engine
from sosya.catalog.models import Entry
from sosya.catalog.search import Hit

MAX_PORTS = 4


def host_platform() -> str | None:
    """The Docker Engine's platform, or Python's guess when the daemon does not answer.

    The guess is only a fallback for `sosya catalog` without Docker: it is wrong under Rosetta
    and with a remote Docker context. Nothing that starts containers uses it.
    """
    return engine.docker_platform() or engine.normalize_platform("linux", platform.machine())


def _ports(entry: Entry) -> str:
    ports = sorted(
        {
            f"{p.port}/udp" if p.protocol == "udp" else str(p.port)
            for s in entry.services
            for p in s.ports
        },
        key=lambda text: int(text.split("/")[0]),
    )
    if len(ports) > MAX_PORTS:
        return ", ".join(ports[:MAX_PORTS]) + f" +{len(ports) - MAX_PORTS}"
    return ", ".join(ports)


def flags(entry: Entry, host: str | None) -> Text:
    text = Text()
    marks: list[tuple[str, str]] = []
    if entry.is_dangerous:
        reasons = sorted({reason.reason for reason in entry.dangerous})
        marks.append((f"⚠ {', '.join(reasons)}", "bold red"))
    if entry.platforms is None:
        marks.append(("platform unknown", "dim"))
    elif host and host not in entry.platforms:
        archs = ", ".join(p.removeprefix("linux/") for p in entry.platforms) or "none"
        marks.append((f"{archs} only", "yellow"))
    if not entry.image_only:
        marks.append(("local files", "cyan"))
    for position, (label, style) in enumerate(marks):
        if position:
            text.append(" · ", style="dim")
        text.append(label, style=style)
    return text


def results_table(hits: Sequence[Hit], host: str | None) -> Table:
    table = Table(header_style="bold", show_edge=False, pad_edge=False, expand=False)
    table.add_column("Environment", style="bold", no_wrap=True)
    table.add_column("Title", overflow="fold", ratio=3)
    table.add_column("Ports", overflow="fold", ratio=1)
    table.add_column("Notes", overflow="fold", ratio=2)
    for hit in hits:
        entry = hit.entry
        title = Text(entry.title)
        if entry.cves and not all(cve in entry.title for cve in entry.cves):
            title.append("\n" + ", ".join(entry.cves), style="dim")
        table.add_row(entry.path, title, _ports(entry) or "-", flags(entry, host))
    return table


def results_json(hits: Sequence[Hit]) -> str:
    data = [
        {
            "score": hit.score,
            "matched": list(hit.matched),
            "entry": hit.entry.model_dump(mode="json"),
        }
        for hit in hits
    ]
    return json.dumps(data, indent=2, ensure_ascii=False)

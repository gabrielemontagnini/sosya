"""Development only: turn one Vulhub environment into a catalog `Entry`.

Every function here is pure: it takes file contents, never touches the network and never
reads the disk, so the tests can feed it small inline fixtures.
"""

import re
from collections.abc import Callable, Mapping
from typing import Any

import yaml

from sosya.catalog.models import DangerReason, Entry, LocalFile, Port, Service

SUMMARY_MAX = 500
COLONS = ":\uff1a"  # ASCII and full-width colon
HOST_NAMESPACES = ("network_mode", "pid", "ipc")
_URL = re.compile(r"https?://[^\s<>()\[\]]+")
_MD_LINK = re.compile(r"!?\[([^\]]*)\]\(([^)]*)\)")
_ANGLE_URL = re.compile(r"<(https?://[^>]+)>")
# A paragraph that starts telling the reader how to run or attack the environment ends the
# summary: SCENARIO.md must never carry step-by-step instructions.
_SETUP = re.compile(r"docker[ -]compose|following command|build and run|```|!\[", re.IGNORECASE)
_CHINESE_LINK = re.compile(r"Chinese version|中文版本")
# Sections that only describe the vulnerability; any other heading ends the intro.
DESCRIPTIVE_SECTIONS = frozenset(
    {
        "reference",
        "references",
        "reference link",
        "reference links",
        "rationale",
        "overview",
        "introduction",
        "description",
        "vulnerability description",
        "background",
    }
)
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)


class ParseError(ValueError):
    pass


# --- ports -----------------------------------------------------------------------------------


def _expand(spec: str, protocol: str) -> list[Port]:
    if "-" in spec:
        start, end = (int(part) for part in spec.split("-", 1))
        return [Port(port=p, protocol=protocol) for p in range(start, end + 1)]  # type: ignore[arg-type]
    return [Port(port=int(spec), protocol=protocol)]  # type: ignore[arg-type]


def parse_port(item: Any) -> list[Port]:
    """Container-side ports of one `ports:` or `expose:` item, short or long syntax."""
    if isinstance(item, Mapping):
        return _expand(str(item["target"]), str(item.get("protocol", "tcp")))
    text = str(item)
    protocol = "tcp"
    if "/" in text:
        text, protocol = text.rsplit("/", 1)
    return _expand(text.rsplit(":", 1)[-1], protocol)


def service_ports(service: Mapping[str, Any]) -> list[Port]:
    seen: dict[tuple[int, str], Port] = {}
    for item in [*service.get("ports", []), *service.get("expose", [])]:
        for port in parse_port(item):
            seen.setdefault((port.port, port.protocol), port)
    return sorted(seen.values(), key=lambda p: (p.port, p.protocol))


# --- local files and privileges --------------------------------------------------------------


def _is_host_path(source: str) -> bool:
    return source.startswith((".", "/", "~"))


def _volume_source(volume: Any) -> tuple[str | None, bool]:
    """Return (source, is_bind) for one `volumes:` item."""
    if isinstance(volume, Mapping):
        source = volume.get("source")
        return source, volume.get("type") == "bind"
    parts = str(volume).split(":")
    if len(parts) < 2:
        return None, False  # anonymous volume
    return parts[0], _is_host_path(parts[0])


def local_files(name: str, service: Mapping[str, Any]) -> list[LocalFile]:
    files: list[LocalFile] = []
    build = service.get("build")
    if build is not None:
        context = build if isinstance(build, str) else build.get("context", ".")
        files.append(LocalFile(service=name, kind="build", source=str(context)))
    for volume in service.get("volumes", []):
        source, is_bind = _volume_source(volume)
        if source and is_bind:
            files.append(LocalFile(service=name, kind="bind", source=source))
    env_files = service.get("env_file", [])
    for item in [env_files] if isinstance(env_files, str | Mapping) else env_files:
        path = item["path"] if isinstance(item, Mapping) else item
        files.append(LocalFile(service=name, kind="env_file", source=str(path)))
    return files


def danger_reasons(name: str, service: Mapping[str, Any]) -> list[DangerReason]:
    """Host-level privileges, with the rules of docs/architecture.md."""
    reasons: list[str] = []
    if service.get("privileged") is True:
        reasons.append("privileged")
    reasons.extend(f"cap_add: {cap}" for cap in service.get("cap_add", []))
    reasons.extend(f"{key}: host" for key in HOST_NAMESPACES if service.get(key) == "host")
    for volume in service.get("volumes", []):
        source, _ = _volume_source(volume)
        if source and source.rstrip("/").endswith("docker.sock"):
            reasons.append("docker.sock mount")
    if service.get("devices"):
        reasons.append("devices")
    return [DangerReason(service=name, reason=reason) for reason in reasons]


# --- Dockerfiles -----------------------------------------------------------------------------


def final_base_image(dockerfile: str) -> str | None:
    """The image of the last `FROM`, or None if it uses a build argument or a stage name."""
    matches = _FROM.findall(dockerfile)
    if not matches:
        return None
    image = matches[-1]
    stages = {
        m.group(1).lower()
        for m in re.finditer(r"^\s*FROM\s+\S+\s+AS\s+(\S+)", dockerfile, re.I | re.M)
    }
    if "$" in image or image.lower() in stages:
        return None
    return image


def _dockerfile_name(service: Mapping[str, Any]) -> str:
    build = service["build"]
    if isinstance(build, Mapping):
        context = str(build.get("context", ".")).strip("/")
        name = str(build.get("dockerfile", "Dockerfile"))
        return name if context in ("", ".") else f"{context.removeprefix('./')}/{name}"
    context = str(build).strip("/")
    return "Dockerfile" if context in ("", ".") else f"{context.removeprefix('./')}/Dockerfile"


# --- README ----------------------------------------------------------------------------------


def _plain(text: str) -> str:
    text = _MD_LINK.sub(lambda m: m.group(1), text)
    text = _ANGLE_URL.sub(lambda m: m.group(1), text)
    text = text.replace("**", "").replace("`", "")
    return " ".join(text.split())


def _truncate(text: str, limit: int = SUMMARY_MAX) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind("。"))
    if end >= limit // 2:
        return cut[: end + 1]
    return cut[: cut.rfind(" ")].rstrip(",;:") + "…"


def parse_readme(readme: str) -> tuple[str | None, str, list[str]]:
    """Return (title, summary, references) from the intro of an English Vulhub README.

    Only the text between the H1 and the first section heading is read, and the summary stops
    at the first paragraph that explains how to run or attack the environment.
    """
    lines = readme.splitlines()
    title: str | None = None
    intro: list[str] = []
    for line in lines:
        if title is None:
            if line.startswith("# "):
                title = line[2:].strip()
            continue
        if line.startswith("#"):
            heading = line.lstrip("#").strip().rstrip(COLONS).lower()
            if heading not in DESCRIPTIVE_SECTIONS:
                break
            intro.extend(["", f"{heading}:" if heading.startswith("reference") else "", ""])
            continue
        intro.append(line)
    paragraphs = [p.strip() for p in "\n".join(intro).split("\n\n") if p.strip()]
    summary: list[str] = []
    references: list[str] = []
    stopped = False
    for paragraph in paragraphs:
        if _CHINESE_LINK.search(paragraph):
            continue
        if _SETUP.search(paragraph):
            stopped = True
        is_list = all(line.lstrip().startswith(("-", "*")) for line in paragraph.splitlines())
        is_label = paragraph.rstrip(COLONS).lower() in DESCRIPTIVE_SECTIONS
        is_url = _URL.fullmatch(_plain(paragraph)) is not None
        if is_list or is_label or is_url:
            if not stopped:
                references.extend(url.rstrip(".,") for url in _URL.findall(paragraph))
            continue
        # A paragraph ending with a colon only introduces a list, a command or a link.
        if not stopped and not paragraph.rstrip().endswith(tuple(COLONS)):
            summary.append(_plain(paragraph.lstrip("> ")))
    return title, _truncate(" ".join(summary)), list(dict.fromkeys(references))


# --- entry -----------------------------------------------------------------------------------


def parse_environment(
    meta: Mapping[str, Any],
    compose_text: str,
    readme_text: str,
    read_file: Callable[[str], str | None],
) -> Entry:
    """Build an `Entry` without platforms. `read_file` returns a file of the environment."""
    path = str(meta["path"])
    compose = yaml.safe_load(compose_text)
    if not isinstance(compose, Mapping) or not isinstance(compose.get("services"), Mapping):
        raise ParseError(f"{path}: docker-compose.yml has no services")
    services: list[Service] = []
    files: list[LocalFile] = []
    dangerous: list[DangerReason] = []
    for name, service in compose["services"].items():
        base_images: list[str] = []
        build_context: str | None = None
        if "build" in service:
            files_for_build = local_files(name, service)
            build_context = files_for_build[0].source
            dockerfile = read_file(_dockerfile_name(service))
            base = final_base_image(dockerfile) if dockerfile else None
            base_images = [base] if base else []
        services.append(
            Service(
                name=name,
                image=service.get("image"),
                build_context=build_context,
                base_images=base_images,
                ports=service_ports(service),
            )
        )
        files.extend(local_files(name, service))
        dangerous.extend(danger_reasons(name, service))
    title, summary, references = parse_readme(readme_text)
    return Entry(
        id=f"vulhub/{path}",
        path=path,
        product=str(meta.get("app", path.split("/")[0])),
        product_dir=path.split("/")[0],
        cves=sorted({cve.upper() for cve in meta.get("cve", [])}),
        title=title or str(meta.get("name", path)),
        summary=summary,
        references=references,
        tags=list(meta.get("tags", [])),
        services=services,
        local_files=files,
        dangerous=dangerous,
    )


def platform_image(service: Service) -> str | None:
    """The image whose platforms decide where `service` runs."""
    if service.build_context is not None:
        return service.base_images[0] if service.base_images else None
    return service.image


def with_platforms(entry: Entry, lookup: Callable[[str], list[str] | None]) -> Entry:
    services = []
    for service in entry.services:
        image = platform_image(service)
        platforms = lookup(image) if image else None
        services.append(service.model_copy(update={"platforms": platforms}))
    return entry.model_copy(update={"services": services})

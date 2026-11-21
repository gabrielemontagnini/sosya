"""The `range.yaml` schema (`apiVersion: sosya/v1`) and its checks against the catalog.

Validation has two layers. The Pydantic models check the structure and the coherence of the
file on its own. `check_catalog` then checks it against the catalog and the engine: components
that exist, names that do not clash, dangerous environments and image platforms. Both report
messages that a person, the planner's repair loop and the MCP server can act on.
"""

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from sosya import topology
from sosya.catalog.loader import load_services
from sosya.catalog.models import CatalogIndex, Entry
from sosya.catalog.rules import RuleError, check_service, interpolate

API_VERSION = "sosya/v1"
RANGE_FILE = "range.yaml"
RESERVED_NETWORKS = frozenset({topology.EGRESS, "proxy", "expose"})
RESERVED_HOSTS = frozenset({topology.ATTACKER})
_FLAG_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
EMULATED = {"linux/arm64": "linux/amd64"}
"""Host platform → foreign platform it can usually run under emulation."""

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$")]
RangeName = Annotated[str, StringConstraints(pattern=r"^[a-z](?:[a-z0-9-]{0,38}[a-z0-9])?$")]
Component = Annotated[str, StringConstraints(pattern=r"^vulhub/[A-Za-z0-9._/-]+$")]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


def _unique(values: list[str], what: str) -> list[str]:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ValueError(f"duplicate {what}: {', '.join(duplicates)}")
    return values


class Host(_Model):
    name: Slug
    component: Component
    networks: Annotated[list[Slug], Field(min_length=1)]
    service: str | None = None
    """The component's service that takes the host's DNS name. Default: the first with ports."""
    flag: str | None = None

    @model_validator(mode="after")
    def _check(self) -> "Host":
        if self.name in RESERVED_HOSTS:
            raise ValueError(f"host name {self.name!r} is reserved")
        _unique(self.networks, f"networks on host {self.name}")
        if self.flag is not None and (
            not _FLAG_PATH.fullmatch(self.flag) or "/../" in f"{self.flag}/"
        ):
            raise ValueError(
                f"flag of host {self.name} must be an absolute path of letters, digits, "
                "'.', '_', '-' and '/'"
            )
        return self


class Attacker(_Model):
    networks: Annotated[list[Slug], Field(min_length=1)]
    internet: bool = True


class RangeSpec(_Model):
    api_version: Literal["sosya/v1"] = Field(alias="apiVersion")
    name: RangeName
    description: str = ""
    networks: Annotated[list[Slug], Field(min_length=1)]
    hosts: Annotated[list[Host], Field(min_length=1)]
    attacker: Attacker
    objectives: list[str] = []

    @model_validator(mode="after")
    def _coherent(self) -> "RangeSpec":
        _unique(self.networks, "networks")
        reserved = sorted(set(self.networks) & RESERVED_NETWORKS)
        if reserved:
            raise ValueError(f"network names reserved by Sosya: {', '.join(reserved)}")
        _unique([host.name for host in self.hosts], "host names")
        declared = set(self.networks)
        used: set[str] = set(self.attacker.networks)
        _unique(self.attacker.networks, "attacker networks")
        for host in self.hosts:
            unknown = sorted(set(host.networks) - declared)
            if unknown:
                raise ValueError(
                    f"host {host.name} joins undeclared networks: {', '.join(unknown)}"
                )
            used |= set(host.networks)
        unknown = sorted(set(self.attacker.networks) - declared)
        if unknown:
            raise ValueError(f"attacker joins undeclared networks: {', '.join(unknown)}")
        unused = [network for network in self.networks if network not in used]
        if unused:
            raise ValueError(f"networks declared but not used: {', '.join(unused)}")
        if not any(set(host.networks) & set(self.attacker.networks) for host in self.hosts):
            raise ValueError("the attacker shares no network with any host: nothing is reachable")
        return self

    def to_yaml(self) -> str:
        data = self.model_dump(mode="json", by_alias=True, exclude_defaults=False)
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


class SpecError(ValueError):
    """A range.yaml that cannot be read or does not match the schema."""


def _location(loc: tuple[Any, ...]) -> str:
    text = ""
    for part in loc:
        text += f"[{part}]" if isinstance(part, int) else (f".{part}" if text else str(part))
    return text


def parse_range(data: Any, source: str = RANGE_FILE) -> RangeSpec:
    try:
        return RangeSpec.model_validate(data)
    except ValidationError as exc:
        lines = []
        for error in exc.errors():
            where = _location(tuple(error["loc"]))
            message = error["msg"].removeprefix("Value error, ")
            lines.append(f"{where}: {message}" if where else message)
        raise SpecError(f"{source} is not a valid range:\n  " + "\n  ".join(lines)) from None


def range_file(path: Path) -> Path:
    return path / RANGE_FILE if path.is_dir() else path


def load_range(path: Path) -> RangeSpec:
    """Read a range from a `range.yaml` file or from a directory that contains one."""
    file = range_file(path)
    try:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SpecError(f"{file} does not exist") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise SpecError(f"cannot read {file}: {exc}") from None
    except yaml.YAMLError as exc:
        raise SpecError(f"{file} is not valid YAML: {exc}") from None
    return parse_range(data, str(file))


# --- checks against the catalog --------------------------------------------------------------


@dataclass(frozen=True)
class Issue:
    level: Literal["error", "warning"]
    message: str
    host: str = ""

    def __str__(self) -> str:
        return f"{self.host}: {self.message}" if self.host else self.message


def errors(issues: list[Issue]) -> list[Issue]:
    return [issue for issue in issues if issue.level == "error"]


def _suggest(component: str, index: CatalogIndex) -> str:
    ids = [entry.id for entry in index.entries]
    close = difflib.get_close_matches(component, ids, n=3, cutoff=0.6)
    return f" Did you mean {', '.join(close)}?" if close else " Search with `sosya catalog`."


def platform_issue(entry: Entry, host: str, host_platform: str) -> Issue | None:
    platforms = entry.platforms
    if platforms is None:
        return Issue("error", f"{entry.id}: an image cannot be pulled (unknown platform)", host)
    if host_platform in platforms:
        return None
    foreign = EMULATED.get(host_platform)
    if foreign in platforms:
        return Issue(
            "warning",
            f"{entry.id} runs on {host_platform} only under emulation ({foreign} images): "
            "it will be slow and may not work",
            host,
        )
    return Issue(
        "error",
        f"{entry.id} cannot run on {host_platform}: its images are {', '.join(platforms)}",
        host,
    )


def _component_issues(
    host: Host, entry: Entry, services: dict[str, Any], allow_privileged: bool
) -> list[Issue]:
    issues: list[Issue] = []
    if host.service is not None and host.service not in services:
        names = ", ".join(services)
        issues.append(
            Issue(
                "error", f"{entry.id} has no service {host.service!r} (it has {names})", host.name
            )
        )
    for name, definition in services.items():
        siblings = frozenset(services) - {name}
        refused = check_service(definition, siblings).unsupported
        issues.extend(
            Issue("error", f"{entry.id}: service {name}: {problem} is not supported", host.name)
            for problem in refused
        )
        try:
            interpolate(definition)
        except RuleError as exc:
            issues.append(Issue("error", f"{entry.id}: service {name}: {exc}", host.name))
    if entry.is_dangerous:
        reasons = "; ".join(f"{d.service}: {d.reason}" for d in entry.dangerous)
        if allow_privileged:
            issues.append(
                Issue("warning", f"{entry.id} gets host-level privileges ({reasons})", host.name)
            )
        else:
            issues.append(
                Issue(
                    "error",
                    f"{entry.id} gets host-level privileges ({reasons}); it starts only with "
                    "--allow-privileged and a confirmation",
                    host.name,
                )
            )
    return issues


def check_catalog(
    spec: RangeSpec,
    index: CatalogIndex,
    *,
    host_platform: str | None,
    allow_privileged: bool = False,
    services_of: Callable[[str], dict[str, Any]] = load_services,
) -> list[Issue]:
    """Check a structurally valid range against the catalog and the engine's platform.

    `host_platform` comes from the Docker daemon (`sosya.engine.docker_platform`); None skips
    the platform check, for planning without Docker.
    """
    issues: list[Issue] = []
    resolved = True
    for host in spec.hosts:
        entry = index.get(host.component)
        if entry is None:
            message = f"{host.component} is not in the catalog." + _suggest(host.component, index)
            issues.append(Issue("error", message, host.name))
            resolved = False
            continue
        services = services_of(entry.id)
        issues.extend(_component_issues(host, entry, services, allow_privileged))
        if host.service is not None and host.service not in services:
            resolved = False
        if host_platform is not None:
            issue = platform_issue(entry, host.name, host_platform)
            if issue is not None:
                issues.append(issue)
    if resolved:
        plan = topology.build(spec, services_of)
        issues.extend(
            Issue("error", message, host) for host, message in topology.name_problems(plan)
        )
    return issues

"""What Sosya accepts in a Vulhub service definition, and what gives a service host-level access.

The catalog builder uses these rules to flag dangerous environments, and the renderer uses the
same rules to refuse anything not allowed. With one source of truth, a key can never look
harmless to one of them and slip through the other.

The allowlist comes from an inventory of all 334 compose files at the pinned Vulhub commit
(2026-11-21). A key that is not listed here makes the catalog build and the renderer fail with
the environment id, so a new Vulhub pin cannot bring in an unreviewed key.
"""

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Keys copied into the rendered service as they are (after interpolation).
SAFE_KEYS: dict[str, str] = {
    "image": "image reference, pinned by the catalog",
    "build": "local build; its context must stay inside the component directory",
    "command": "process arguments",
    "entrypoint": "process arguments",
    "environment": "process environment",
    "env_file": "process environment, read from the component directory",
    "depends_on": "start order; names are rewritten to the rendered service names",
    "healthcheck": "runs inside the container",
    "user": "user inside the container",
    "restart": "restart policy; `always` and `unless-stopped` become `on-failure`",
    "hostname": "name inside the container's own UTS namespace",
    "working_dir": "path inside the container",
    "init": "adds an init process inside the container",
    "tty": "allocates a pseudo-terminal",
    "shm_size": "size of the container's own /dev/shm",
    "ulimits": "per-container limits; they cannot exceed the daemon's hard limits",
    "labels": "metadata; `sosya.*` and `com.docker.*` labels are refused",
    "volumes": "checked item by item: binds must stay inside the component directory",
    "expose": "documents container ports; publishes nothing",
}

# Keys the renderer consumes: they never reach the rendered service as they are.
REWRITTEN_KEYS: dict[str, str] = {
    "ports": "removed: targets never publish ports",
    "container_name": "removed: a global name would collide across ranges",
    "links": "translated to network aliases on the component's private network",
    "networks": "replaced by the range's own networks",
}

# Keys that weaken isolation or give access to the host. They are allowed only in environments
# flagged dangerous, which start only with `--allow-privileged` and a confirmation.
HOST_LEVEL_KEYS = frozenset(
    {
        "privileged",
        "cap_add",
        "devices",
        "security_opt",
        "network_mode",
        "pid",
        "ipc",
        "userns_mode",
    }
)
HOST_NAMESPACES = ("pid", "ipc", "userns_mode")

_INTERPOLATION = re.compile(r"\$\$|\$\{([^}]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_DEFAULT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(:?-)(.*)$", re.DOTALL)


class RuleError(ValueError):
    """A service definition that Sosya does not accept."""


@dataclass(frozen=True)
class Volume:
    source: str | None
    target: str
    is_bind: bool
    """True when `source` is a host path, which Vulhub always writes relative to the component."""


@dataclass(frozen=True)
class ServiceCheck:
    dangerous: list[str]
    """Host-level privileges, as human-readable reasons."""
    unsupported: list[str]
    """Keys or values that Sosya refuses in any environment."""


def is_host_path(source: str) -> bool:
    return source.startswith((".", "/", "~"))


def parse_volume(volume: Any) -> Volume | None:
    """A short-syntax `volumes:` item, or None for the long syntax (not used by Vulhub)."""
    if isinstance(volume, Mapping):
        return None
    parts = str(volume).split(":")
    if len(parts) == 1:
        return Volume(source=None, target=parts[0], is_bind=False)  # anonymous volume
    return Volume(source=parts[0], target=parts[1], is_bind=is_host_path(parts[0]))


def stays_inside(source: str) -> bool:
    """True when a host path is relative and does not leave the component directory."""
    if source.startswith(("/", "~")):
        return False
    normalized = posixpath.normpath(source)
    return normalized != ".." and not normalized.startswith("../")


def _volume_issues(volume: Any) -> tuple[list[str], list[str]]:
    parsed = parse_volume(volume)
    if parsed is None:
        return [], [f"long-syntax volume {dict(volume)!r}"]
    if parsed.source is None:
        return [], []
    if not parsed.is_bind:
        return [], [f"named volume {parsed.source!r}"]
    if parsed.source.rstrip("/").endswith("docker.sock"):
        return ["docker.sock mount"], []
    if not stays_inside(parsed.source):
        return [f"bind mount outside the component: {parsed.source}"], []
    return [], []


def check_service(service: Mapping[str, Any], siblings: frozenset[str]) -> ServiceCheck:
    """Classify one service. `siblings` are the other services of the same component."""
    dangerous: list[str] = []
    unsupported: list[str] = []
    for key in service:
        if key not in SAFE_KEYS and key not in REWRITTEN_KEYS and key not in HOST_LEVEL_KEYS:
            unsupported.append(f"key {key!r}")
    if service.get("privileged") is True:
        dangerous.append("privileged")
    elif service.get("privileged") not in (None, False):
        unsupported.append(f"privileged: {service['privileged']!r}")
    dangerous.extend(f"cap_add: {cap}" for cap in service.get("cap_add", []))
    if service.get("devices"):
        dangerous.append("devices")
    dangerous.extend(f"security_opt: {opt}" for opt in service.get("security_opt", []))
    network_mode = service.get("network_mode")
    if network_mode is not None:
        target = str(network_mode).removeprefix("service:")
        if not (str(network_mode).startswith("service:") and target in siblings):
            dangerous.append(f"network_mode: {network_mode}")
    for key in HOST_NAMESPACES:
        if key not in service:
            continue
        if service[key] == "host":
            dangerous.append(f"{key}: host")
        else:
            unsupported.append(f"{key}: {service[key]!r}")
    for volume in service.get("volumes", []):
        danger, refused = _volume_issues(volume)
        dangerous.extend(danger)
        unsupported.extend(refused)
    build = service.get("build")
    if build is not None:
        context = build if isinstance(build, str) else build.get("context", ".")
        if not stays_inside(str(context)):
            unsupported.append(f"build context outside the component: {context}")
    return ServiceCheck(dangerous=dangerous, unsupported=unsupported)


def _resolve(match: re.Match[str]) -> str:
    if match.group(0) == "$$":
        return "$$"  # an escaped dollar: Compose turns it into `$`
    body = match.group(1)
    if body is not None:
        default = _DEFAULT.match(body)
        if default and "$" not in default.group(3):
            return default.group(3)
    raise RuleError(
        f"interpolation {match.group(0)} has no default: the rendered range must not depend "
        "on the caller's environment"
    )


def interpolate(value: Any) -> Any:
    """Replace `${VAR:-default}` and `${VAR-default}` with their default, everywhere in `value`.

    The rendered compose file must not depend on the environment of whoever runs `sosya up`.
    `$$` (an escaped dollar) is kept. Any other form raises `RuleError`.
    """
    if isinstance(value, str):
        return _INTERPOLATION.sub(_resolve, value)
    if isinstance(value, Mapping):
        return {key: interpolate(item) for key, item in value.items()}
    if isinstance(value, list):
        return [interpolate(item) for item in value]
    return value

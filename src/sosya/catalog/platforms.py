"""Development only: find the platforms of every image the catalog references.

Images on Docker Hub are looked up through the Docker Hub web API
(`hub.docker.com/v2/repositories/<namespace>/<repo>/tags/<tag>`, field `images`). That API
does not touch the registry, so it does not use up the registry pull limit that `sosya up`
needs. `docker buildx imagetools inspect` is the fallback: for other registries, and for
Docker Hub images when the web API does not answer. On Docker Hub the fallback reads
manifests from the registry, which counts against the pull limit, so it runs only for a user
logged in with `docker login`.

Results go to a JSON cache, written after every image: an interrupted run loses at most the
image in progress, and the next run starts from the images still missing.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HUB_API = "https://hub.docker.com/v2/repositories/{repository}/tags/{tag}"
HUB_REGISTRY_KEYS = ("https://index.docker.io/v1/", "index.docker.io", "docker.io")
DEFAULT_CACHE = Path("data/vulhub-platforms.json")
MAX_RATE_LIMIT_WAIT = 120.0
USER_AGENT = "sosya-catalog-builder"

SOURCE_HUB = "hub-api"
SOURCE_IMAGETOOLS = "imagetools"


# --- image references ------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageRef:
    registry: str  # "docker.io" for Docker Hub
    repository: str  # "library/mysql" for official images
    tag: str | None
    digest: str | None

    @property
    def on_docker_hub(self) -> bool:
        return self.registry == "docker.io"


def parse_ref(ref: str) -> ImageRef:
    name, _, digest_part = ref.partition("@")
    digest = digest_part or None
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", name
    tag: str | None = None
    if ":" in path.rsplit("/", 1)[-1]:
        path, tag = path.rsplit(":", 1)
    if tag is None and digest is None:
        tag = "latest"
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    return ImageRef(registry=registry, repository=path, tag=tag, digest=digest)


def platform_string(os_name: str, architecture: str, variant: str | None) -> str | None:
    """`linux/arm/v7` style string; None for attestation entries (`unknown/unknown`)."""
    if not os_name or not architecture or "unknown" in (os_name, architecture):
        return None
    if architecture == "arm64" and variant == "v8":
        variant = None  # Docker treats linux/arm64/v8 and linux/arm64 as the same platform
    return "/".join(part for part in (os_name, architecture, variant) if part)


def _platforms(items: Iterable[Mapping[str, Any]]) -> list[str]:
    found = {
        platform_string(item.get("os", ""), item.get("architecture", ""), item.get("variant"))
        for item in items
    }
    return sorted(p for p in found if p)


# --- errors ----------------------------------------------------------------------------------


class LookupFailed(RuntimeError):
    """The source could not answer; another source may."""


class NotFound(RuntimeError):
    """The image or tag does not exist."""


class RateLimited(RuntimeError):
    def __init__(self, message: str, reset_at: float | None = None) -> None:
        super().__init__(message)
        self.reset_at = reset_at


# --- Docker Hub web API ----------------------------------------------------------------------


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


HttpGet = Callable[[str], HttpResponse]


def urllib_get(url: str, timeout: float = 20.0) -> HttpResponse:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(response.status, dict(response.headers), response.read())
    except urllib.error.HTTPError as error:
        return HttpResponse(error.code, dict(error.headers or {}), error.read() or b"")
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise LookupFailed(f"Docker Hub API unreachable: {error}") from error


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def hub_platforms(ref: ImageRef, http_get: HttpGet) -> list[str]:
    if ref.tag is None:
        raise LookupFailed("the Docker Hub tags API needs a tag, not a digest")
    response = http_get(HUB_API.format(repository=ref.repository, tag=ref.tag))
    if response.status == 404:
        raise NotFound(f"{ref.repository}:{ref.tag} not found on Docker Hub")
    if response.status == 429:
        reset = _header(response.headers, "x-ratelimit-reset")
        raise RateLimited("Docker Hub API rate limit", float(reset) if reset else None)
    if response.status != 200:
        raise LookupFailed(f"Docker Hub API answered HTTP {response.status}")
    try:
        images = json.loads(response.body)["images"]
    except (ValueError, KeyError, TypeError) as error:
        raise LookupFailed("Docker Hub API sent an unexpected answer") from error
    platforms = _platforms(images)
    if not platforms:
        raise LookupFailed("Docker Hub API listed no platforms")
    return platforms


# --- docker buildx imagetools (fallback) -----------------------------------------------------

Run = Callable[..., subprocess.CompletedProcess[str]]


def _inspect(ref: str, template: str, run: Run) -> Any:
    proc = run(
        ["docker", "buildx", "imagetools", "inspect", "--format", template, ref],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        error = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no output"
        lowered = error.lower()
        if "toomanyrequests" in lowered or "429" in lowered:
            raise RateLimited(f"registry rate limit: {error}")
        if "not found" in lowered:
            raise NotFound(error)
        raise LookupFailed(f"imagetools inspect failed: {error}")
    return json.loads(proc.stdout)


def imagetools_platforms(ref: str, run: Run = subprocess.run) -> list[str]:
    """Platforms from the manifest list, or from the image config of a single manifest."""
    manifest = _inspect(ref, "{{json .Manifest}}", run)
    if "manifests" in manifest:
        platforms = _platforms(m.get("platform", {}) for m in manifest["manifests"])
    else:
        platforms = _platforms([_inspect(ref, "{{json .Image}}", run)])
    if not platforms:
        raise LookupFailed("imagetools found no platforms")
    return platforms


def docker_config_path() -> Path:
    base = os.environ.get("DOCKER_CONFIG")
    return (Path(base) if base else Path.home() / ".docker") / "config.json"


def docker_hub_logged_in(config_path: Path | None = None, run: Run = subprocess.run) -> bool:
    """True if `docker login` stored Docker Hub credentials. Never reads a secret.

    A credential helper's `list` command returns server URLs and user names only.
    """
    path = config_path or docker_config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    auths = config.get("auths", {})
    if any(key in HUB_REGISTRY_KEYS and auths[key].get("auth") for key in auths):
        return True
    helpers = config.get("credHelpers", {})
    helper = next((helpers[k] for k in HUB_REGISTRY_KEYS if k in helpers), None)
    helper = helper or config.get("credsStore")
    if not helper:
        return False
    try:
        proc = run(
            [f"docker-credential-{helper}", "list"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    try:
        servers = json.loads(proc.stdout)
    except ValueError:
        return False
    return any(any(key in server for key in HUB_REGISTRY_KEYS) for server in servers)


# --- cache -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheEntry:
    platforms: list[str] | None
    error: str | None
    source: str | None


def load_cache(path: Path) -> dict[str, CacheEntry]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        ref: CacheEntry(item.get("platforms"), item.get("error"), item.get("source"))
        for ref, item in raw["images"].items()
    }


def save_cache(path: Path, cache: Mapping[str, CacheEntry]) -> None:
    """Write the whole cache atomically, so an interruption never leaves a broken file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "images": {
            ref: {"platforms": e.platforms, "error": e.error, "source": e.source}
            for ref, e in sorted(cache.items())
        }
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def cached_platforms(cache: Mapping[str, CacheEntry]) -> Callable[[str], list[str] | None]:
    return lambda ref: cache[ref].platforms if ref in cache else None


# --- detection -------------------------------------------------------------------------------


@dataclass
class DetectReport:
    checked: list[str] = field(default_factory=list)
    skipped: int = 0
    not_found: list[str] = field(default_factory=list)
    needs_login: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    rate_limited: str | None = None
    remaining: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not (self.rate_limited or self.needs_login or self.failed or self.remaining)


def _todo(images: Iterable[str], cache: Mapping[str, CacheEntry], mode: str) -> list[str]:
    if mode == "all":
        return sorted(set(images))
    if mode == "errors":
        return sorted(i for i in set(images) if i not in cache or cache[i].platforms is None)
    return sorted(i for i in set(images) if i not in cache)


def detect(
    images: Iterable[str],
    cache_path: Path = DEFAULT_CACHE,
    *,
    refresh: str = "missing",
    delay: float = 1.0,
    http_get: HttpGet = urllib_get,
    run: Run = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
    logged_in: Callable[[], bool] | None = None,
    on_result: Callable[[str, CacheEntry], None] | None = None,
) -> DetectReport:
    """Look up the platforms of `images` and record them in the cache at `cache_path`.

    `refresh` is "missing" (only images not in the cache), "errors" (also retry failures) or
    "all". The run stops early, with `report.rate_limited` set, when a rate limit would make
    it wait longer than `MAX_RATE_LIMIT_WAIT` seconds.
    """
    cache = load_cache(cache_path)
    todo = _todo(images, cache, refresh)
    report = DetectReport(skipped=len(set(images)) - len(todo))
    login_state: bool | None = None

    def hub_login() -> bool:
        nonlocal login_state
        if login_state is None:
            login_state = logged_in() if logged_in else docker_hub_logged_in(run=run)
        return login_state

    for position, image in enumerate(todo):
        ref = parse_ref(image)
        try:
            entry = _lookup(image, ref, http_get, run, sleep, now, hub_login)
        except RateLimited as error:
            report.rate_limited = str(error)
            report.remaining = todo[position:]
            break
        except _NeedsLogin:
            report.needs_login.append(image)
            continue
        except LookupFailed as error:
            report.failed.append(image)
            entry = CacheEntry(None, str(error), None)
        else:
            if entry.platforms is None:
                report.not_found.append(image)
        cache[image] = entry
        save_cache(cache_path, cache)
        report.checked.append(image)
        if on_result:
            on_result(image, entry)
        if delay and position + 1 < len(todo):
            sleep(delay)
    return report


class _NeedsLogin(RuntimeError):
    pass


def _lookup(
    image: str,
    ref: ImageRef,
    http_get: HttpGet,
    run: Run,
    sleep: Callable[[float], None],
    now: Callable[[], float],
    hub_login: Callable[[], bool],
) -> CacheEntry:
    if ref.on_docker_hub and ref.tag is not None:
        for attempt in range(2):
            try:
                return CacheEntry(hub_platforms(ref, http_get), None, SOURCE_HUB)
            except NotFound as error:
                return CacheEntry(None, str(error), SOURCE_HUB)
            except RateLimited as error:
                # Waiting is cheap; falling back to the registry would spend pull limit.
                wait = (error.reset_at - now()) if error.reset_at else None
                if attempt or wait is None or wait > MAX_RATE_LIMIT_WAIT:
                    raise
                sleep(max(wait, 0.0) + 1.0)
            except LookupFailed:
                break
        if not hub_login():
            raise _NeedsLogin(image)
    try:
        return CacheEntry(imagetools_platforms(image, run), None, SOURCE_IMAGETOOLS)
    except NotFound as error:
        return CacheEntry(None, str(error), SOURCE_IMAGETOOLS)

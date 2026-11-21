import json
import subprocess
from pathlib import Path

import pytest

from sosya.catalog import platforms as pf
from sosya.catalog.platforms import (
    CacheEntry,
    HttpResponse,
    ImageRef,
    detect,
    docker_hub_logged_in,
    imagetools_platforms,
    load_cache,
    parse_ref,
    platform_string,
)


def _hub(images: list[dict] | None = None, status: int = 200, headers=None) -> HttpResponse:
    body = json.dumps({"images": images or []}).encode()
    return HttpResponse(status, headers or {}, body)


AMD64 = {"os": "linux", "architecture": "amd64", "variant": None}
ARM64 = {"os": "linux", "architecture": "arm64", "variant": "v8"}
ATTESTATION = {"os": "unknown", "architecture": "unknown", "variant": None}


class FakeHub:
    """Answers the Docker Hub tags API from a dict of url suffix -> response."""

    def __init__(self, answers: dict[str, HttpResponse | Exception]) -> None:
        self.answers = answers
        self.urls: list[str] = []

    def __call__(self, url: str) -> HttpResponse:
        self.urls.append(url)
        for suffix, answer in self.answers.items():
            if url.endswith(suffix):
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return _hub(status=404)


def _no_docker(*args, **kwargs):
    raise AssertionError(f"docker must not run: {args}")


def _detect(images, cache: Path, hub: FakeHub, run=_no_docker, **kwargs):
    kwargs.setdefault("logged_in", lambda: False)
    return detect(images, cache, delay=0, http_get=hub, run=run, sleep=lambda s: None, **kwargs)


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("mysql:5.7", ImageRef("docker.io", "library/mysql", "5.7", None)),
        ("redis", ImageRef("docker.io", "library/redis", "latest", None)),
        ("vulhub/struts2:2.3.30", ImageRef("docker.io", "vulhub/struts2", "2.3.30", None)),
        (
            "gcr.io/etcd-development/etcd:v3.4.15",
            ImageRef("gcr.io", "etcd-development/etcd", "v3.4.15", None),
        ),
        ("localhost:5000/app", ImageRef("localhost:5000", "app", "latest", None)),
        ("alpine@sha256:abc", ImageRef("docker.io", "library/alpine", None, "sha256:abc")),
    ],
)
def test_parse_ref(ref: str, expected: ImageRef) -> None:
    assert parse_ref(ref) == expected


def test_platform_string_ignores_attestations_and_normalizes_arm64() -> None:
    assert platform_string("linux", "arm", "v7") == "linux/arm/v7"
    assert platform_string("linux", "arm64", "v8") == "linux/arm64"
    assert platform_string("unknown", "unknown", None) is None


def test_docker_hub_api_comes_first_and_never_runs_docker(tmp_path: Path) -> None:
    hub = FakeHub(
        {
            "library/mysql/tags/5.7": _hub([AMD64, ATTESTATION]),
            "vulhub/redis/tags/4.0.14": _hub([AMD64, ARM64]),
        }
    )
    cache = tmp_path / "cache.json"
    report = _detect(["mysql:5.7", "vulhub/redis:4.0.14"], cache, hub)
    assert report.complete
    assert load_cache(cache) == {
        "mysql:5.7": CacheEntry(["linux/amd64"], None, "hub-api"),
        "vulhub/redis:4.0.14": CacheEntry(["linux/amd64", "linux/arm64"], None, "hub-api"),
    }
    assert hub.urls[0] == "https://hub.docker.com/v2/repositories/library/mysql/tags/5.7"


def test_not_found_on_docker_hub_is_cached_as_an_error(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    report = _detect(["vulhub/gone:1"], cache, FakeHub({}))
    assert report.not_found == ["vulhub/gone:1"]
    entry = load_cache(cache)["vulhub/gone:1"]
    assert entry.platforms is None
    assert "not found" in (entry.error or "")


def _imagetools(manifests: dict[str, dict]):
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        ref, template = cmd[-1], cmd[-2]
        key = "manifest" if "Manifest" in template else "image"
        if ref not in manifests:
            return subprocess.CompletedProcess(cmd, 1, "", f"ERROR: {ref}: not found")
        return subprocess.CompletedProcess(cmd, 0, json.dumps(manifests[ref][key]), "")

    run.calls = calls  # type: ignore[attr-defined]
    return run


ETCD = "gcr.io/etcd-development/etcd:v3.4.15"
SINGLE = {"manifest": {"mediaType": "x", "digest": "sha256:1"}, "image": AMD64}
INDEX = {
    "manifest": {
        "manifests": [{"platform": AMD64}, {"platform": ARM64}, {"platform": ATTESTATION}]
    },
    "image": {},
}


def test_imagetools_reads_a_manifest_list() -> None:
    assert imagetools_platforms("x:1", _imagetools({"x:1": INDEX})) == [
        "linux/amd64",
        "linux/arm64",
    ]


def test_imagetools_reads_the_config_of_a_single_manifest() -> None:
    run = _imagetools({"x:1": SINGLE})
    assert imagetools_platforms("x:1", run) == ["linux/amd64"]
    assert len(run.calls) == 2


def test_other_registries_use_imagetools_without_login(tmp_path: Path) -> None:
    hub = FakeHub({})
    run = _imagetools({ETCD: SINGLE})
    report = _detect([ETCD], tmp_path / "c.json", hub, run=run)
    assert report.complete
    assert hub.urls == []
    assert load_cache(tmp_path / "c.json")[ETCD] == CacheEntry(["linux/amd64"], None, "imagetools")


def test_hub_api_down_falls_back_only_when_logged_in(tmp_path: Path) -> None:
    hub = FakeHub({"tags/1": pf.LookupFailed("unreachable")})
    run = _imagetools({"vulhub/x:1": SINGLE})
    cache = tmp_path / "c.json"

    report = _detect(["vulhub/x:1"], cache, hub, run=run, logged_in=lambda: False)
    assert report.needs_login == ["vulhub/x:1"]
    assert not report.complete
    assert run.calls == []
    assert load_cache(cache) == {}

    report = _detect(["vulhub/x:1"], cache, hub, run=run, logged_in=lambda: True)
    assert report.complete
    assert load_cache(cache)["vulhub/x:1"].source == "imagetools"


def test_short_rate_limit_waits_and_retries(tmp_path: Path) -> None:
    answers = [_hub(status=429, headers={"X-RateLimit-Reset": "1030"}), _hub([AMD64])]
    waits: list[float] = []
    report = detect(
        ["a:1"],
        tmp_path / "c.json",
        delay=0,
        http_get=lambda url: answers.pop(0),
        run=_no_docker,
        sleep=waits.append,
        now=lambda: 1000.0,
        logged_in=lambda: False,
    )
    assert report.complete
    assert waits == [31.0]


def test_long_rate_limit_stops_and_keeps_progress(tmp_path: Path) -> None:
    limited = _hub(status=429, headers={"x-ratelimit-reset": "999999"})
    hub = FakeHub({"tags/1": _hub([AMD64]), "tags/2": limited})
    cache = tmp_path / "c.json"
    report = _detect(["a:1", "b:2", "c:3"], cache, hub, now=lambda: 0.0)
    assert report.rate_limited
    assert report.remaining == ["b:2", "c:3"]
    assert list(load_cache(cache)) == ["a:1"]


def test_resume_skips_cached_images(tmp_path: Path) -> None:
    cache = tmp_path / "c.json"
    _detect(["a:1"], cache, FakeHub({"tags/1": _hub([AMD64])}))
    hub = FakeHub({"tags/2": _hub([AMD64])})
    report = _detect(["a:1", "b:2"], cache, hub)
    assert report.skipped == 1
    assert report.checked == ["b:2"]
    assert hub.urls == ["https://hub.docker.com/v2/repositories/library/b/tags/2"]


def test_refresh_modes(tmp_path: Path) -> None:
    cache = tmp_path / "c.json"
    _detect(["a:1", "gone:1"], cache, FakeHub({"a/tags/1": _hub([AMD64])}))
    hub = FakeHub({"a/tags/1": _hub([AMD64])})
    assert _detect(["a:1", "gone:1"], cache, hub, refresh="errors").checked == ["gone:1"]
    assert _detect(["a:1", "gone:1"], cache, hub, refresh="all").checked == ["a:1", "gone:1"]


def test_cache_write_is_atomic(tmp_path: Path) -> None:
    cache = tmp_path / "c.json"
    _detect(["a:1"], cache, FakeHub({"tags/1": _hub([AMD64])}))
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]


# --- docker login detection ------------------------------------------------------------------


def _config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return path


def test_login_with_inline_auth(tmp_path: Path) -> None:
    config = _config(tmp_path, {"auths": {"https://index.docker.io/v1/": {"auth": "eA=="}}})
    assert docker_hub_logged_in(config, run=_no_docker)


def test_login_through_a_credential_helper(tmp_path: Path) -> None:
    config = _config(tmp_path, {"auths": {"https://index.docker.io/v1/": {}}, "credsStore": "pass"})
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        listing = json.dumps({"https://index.docker.io/v1/": "someone"})
        return subprocess.CompletedProcess(cmd, 0, listing, "")

    assert docker_hub_logged_in(config, run=run)
    assert calls == [["docker-credential-pass", "list"]]


def test_helper_without_docker_hub_is_not_a_login(tmp_path: Path) -> None:
    config = _config(tmp_path, {"credsStore": "pass"})

    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"ghcr.io": "someone"}), "")

    assert not docker_hub_logged_in(config, run=run)


def test_no_config_is_not_a_login(tmp_path: Path) -> None:
    assert not docker_hub_logged_in(tmp_path / "missing.json", run=_no_docker)

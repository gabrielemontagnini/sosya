import json
import subprocess
from pathlib import Path

import pytest

from sosya.catalog import VULHUB_COMMIT, build, source
from sosya.catalog.models import CatalogIndex
from sosya.catalog.platforms import CacheEntry, save_cache

TOML = """\
[[environment]]
name = "Web RCE"
cve = ["CVE-2099-0001"]
app = "Web"
path = "web/CVE-2099-0001"
tags = ["RCE"]

[[environment]]
name = "Cache unauth"
cve = []
app = "Cache"
path = "cache/unauth"
tags = ["Database"]
"""


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "vulhub"
    (root / "web/CVE-2099-0001").mkdir(parents=True)
    (root / "cache/unauth").mkdir(parents=True)
    (root / "environments.toml").write_text(TOML)
    (root / "web/CVE-2099-0001/docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports: ['8080:8080']\n"
    )
    (root / "web/CVE-2099-0001/Dockerfile").write_text("FROM vulhub/tomcat:8.5\n")
    (root / "web/CVE-2099-0001/README.md").write_text("# Web RCE\n\nWeb has a flaw.\n")
    (root / "cache/unauth/docker-compose.yml").write_text(
        "services:\n  redis:\n    image: vulhub/redis:4.0.14\n    ports: ['6379:6379']\n"
    )
    (root / "cache/unauth/README.md").write_text("# Cache unauth\n\nNo password.\n")
    monkeypatch.setattr(build, "head", lambda path: VULHUB_COMMIT)
    return root


def test_read_environments_and_images(checkout: Path) -> None:
    entries = build.read_environments(checkout)
    assert [e.id for e in entries] == ["vulhub/cache/unauth", "vulhub/web/CVE-2099-0001"]
    assert build.referenced_images(entries) == ["vulhub/redis:4.0.14", "vulhub/tomcat:8.5"]


def test_read_environments_refuses_a_wrong_commit(
    checkout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build, "head", lambda path: "0" * 40)
    with pytest.raises(SystemExit):
        build.read_environments(checkout)


def test_index_is_deterministic_and_round_trips(checkout: Path, tmp_path: Path) -> None:
    cache = tmp_path / "platforms.json"
    save_cache(
        cache,
        {
            "vulhub/redis:4.0.14": CacheEntry(["linux/amd64"], None, "hub-api"),
            "vulhub/tomcat:8.5": CacheEntry(["linux/amd64", "linux/arm64"], None, "hub-api"),
        },
    )
    output = tmp_path / "index.json"
    argv = ["--checkout", str(checkout), "--cache", str(cache), "index", "--output", str(output)]
    assert build.main(argv) == 0
    first = output.read_text()
    assert build.main(argv) == 0
    assert output.read_text() == first
    index = CatalogIndex.model_validate_json(first)
    assert index.vulhub_commit == VULHUB_COMMIT
    web = index.get("vulhub/web/CVE-2099-0001")
    assert web is not None
    assert web.platforms == ["linux/amd64", "linux/arm64"]
    assert "image_only" not in json.loads(first)["entries"][0]


def test_index_refuses_missing_platforms(checkout: Path, tmp_path: Path) -> None:
    output = tmp_path / "index.json"
    argv = ["--checkout", str(checkout), "--cache", str(tmp_path / "none.json")]
    assert build.main([*argv, "index", "--output", str(output)]) == 2
    assert not output.exists()
    assert build.main([*argv, "index", "--output", str(output), "--allow-missing-platforms"]) == 0
    index = CatalogIndex.model_validate_json(output.read_text())
    assert all(entry.platforms is None for entry in index.entries)


def test_sparse_patterns_take_only_text_files() -> None:
    patterns = source.sparse_patterns(["b/x", "a/y"])
    assert patterns[0] == "/environments.toml"
    assert patterns[1:4] == ["/a/y/docker-compose.yml", "/a/y/README.md", "/a/y/Dockerfile*"]
    assert not any(p.endswith((".png", "/")) for p in patterns)


def test_sync_fetches_one_blobless_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    checkout = tmp_path / "vulhub"

    def run(cmd, **kwargs):
        calls.append(cmd[3:])
        if cmd[3:5] == ["checkout", "--quiet"]:
            (checkout / "environments.toml").write_text(TOML)
        stdout = VULHUB_COMMIT if cmd[3] == "rev-parse" else ""
        return subprocess.CompletedProcess(cmd, 0, stdout, "")

    monkeypatch.setattr(source.subprocess, "run", run)
    monkeypatch.setattr(source, "head", lambda path: None)
    with pytest.raises(source.SourceError):
        source.sync(checkout)  # head() still says "not at the commit"
    fetch = next(c for c in calls if c[0] == "fetch")
    assert fetch == [
        "fetch",
        "--quiet",
        "--depth",
        "1",
        "--filter=blob:none",
        "origin",
        VULHUB_COMMIT,
    ]
    sparse = [c for c in calls if c[:2] == ["sparse-checkout", "set"]][-1]
    assert "/web/CVE-2099-0001/docker-compose.yml" in sparse


def test_sync_is_a_no_op_at_the_pinned_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "environments.toml").write_text(TOML)
    monkeypatch.setattr(source, "head", lambda path: VULHUB_COMMIT)
    monkeypatch.setattr(source.subprocess, "run", lambda *a, **k: pytest.fail("git ran"))
    assert source.sync(tmp_path) == tmp_path

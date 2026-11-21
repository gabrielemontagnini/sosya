import io
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest
from snapshot import assert_snapshot
from test_runtime import FakeDocker, container, done, start

from sosya import gallery, runtime
from sosya.catalog.loader import load_index
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker
from sosya.scenario import flags, markdown
from sosya.spec import load_range


def test_flags_are_random_and_well_formed() -> None:
    first, second = flags.new_flag(), flags.new_flag()
    assert first != second
    assert re.fullmatch(r"SOSYA\{[0-9a-f]{32}\}", first)


def test_archive_holds_only_the_file_world_readable() -> None:
    data = flags.archive("flag.txt", b"SOSYA{x}\n")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        (member,) = tar.getmembers()
    assert member.name == "flag.txt" and member.isfile()
    assert member.mode == 0o644 and member.uid == 0
    assert flags.read_archive(data) == b"SOSYA{x}\n"


class CopyRunner:
    """Accept `docker cp -` only into the given directories; keep what was written."""

    def __init__(self, writable: set[str]) -> None:
        self.writable = writable
        self.files: dict[str, bytes] = {}
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        self.calls.append(argv)
        if argv[:3] == ["docker", "cp", "-"]:
            directory = argv[3].split(":", 1)[1]
            if directory not in self.writable:
                return subprocess.CompletedProcess(argv, 1, b"", b"no such directory")
            with tarfile.open(fileobj=io.BytesIO(kwargs["input"])) as tar:
                (member,) = tar.getmembers()
                handle = tar.extractfile(member)
                assert handle is not None
                self.files[f"{directory.rstrip('/')}/{member.name}"] = handle.read()
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[:2] == ["docker", "cp"] and argv[-1] == "-":
            path = argv[2].split(":", 1)[1]
            if path not in self.files:
                return subprocess.CompletedProcess(argv, 1, b"", b"missing")
            name = path.rsplit("/", 1)[1]
            return subprocess.CompletedProcess(argv, 0, flags.archive(name, self.files[path]), b"")
        raise AssertionError(argv)


def test_place_uses_the_default_path_and_reads_it_back() -> None:
    runner = CopyRunner({"/"})
    docker = Docker(runner=runner)
    flag = flags.place(docker, "abc", None)
    assert flag is not None and flag.path == "/flag.txt"
    assert runner.calls[0][:4] == ["docker", "cp", "-", "abc:/"]
    assert flags.read(docker, "abc", "/flag.txt") == flag.value


def test_place_falls_back_to_tmp() -> None:
    runner = CopyRunner({"/tmp"})
    flag = flags.place(Docker(runner=runner), "abc", "/root/flag.txt")
    assert flag is not None and flag.path == "/tmp/flag.txt"


def test_place_gives_up_when_nothing_is_writable() -> None:
    assert flags.place(Docker(runner=CopyRunner(set())), "abc", None) is None


# --- up places flags and writes SCENARIO.md -------------------------------------------------


def test_up_places_flags_and_writes_the_scenario(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    fake.containers = [container("web"), container("cache"), container("attacker", role="attacker")]
    record, log = start(range_dir, workspace, fake)
    assert set(record.flags) == {"web", "cache"}
    assert record.flags["web"]["path"] == "/flag.txt"
    copies = [call for call in fake.calls if call[:3] == ["docker", "cp", "-"]]
    assert len(copies) == 2
    saved = state_store.load(workspace.root)["dmz-redis"]
    assert saved.flags == record.flags
    scenario = workspace.scenario_file("dmz-redis")
    text = scenario.read_text()
    assert "`/flag.txt`" in text
    for flag in record.flags.values():
        assert flag["value"] not in text
        assert flag["value"] not in log.text()
    assert "sosya shell dmz-redis" in log.lines[-1][1]
    assert str(scenario.resolve()) in log.lines[-1][1]


def test_up_warns_when_a_flag_cannot_be_placed(
    range_dir: Path, workspace: runtime.Workspace, fake: FakeDocker
) -> None:
    fake.containers = [container("web"), container("cache")]
    fake.on(lambda a: a[:2] == ["cp", "-"] and a[2].startswith("cache"), lambda a: done(code=1))
    record, log = start(range_dir, workspace, fake)
    assert set(record.flags) == {"web"}
    assert ("warn", "no flag could be placed on cache") in log.lines


def test_old_state_files_without_flags_still_load(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        '{"ranges": {"a": {"name": "a", "project": "sosya-a", "compose_file": "f", '
        '"source": "s", "started_at": "t", "unknown": 1}}}'
    )
    assert state_store.load(tmp_path)["a"].flags == {}


# --- SCENARIO.md ----------------------------------------------------------------------------


def test_scenario_snapshot_of_the_gallery_range() -> None:
    path = gallery.path("dmz-redis")
    assert path is not None
    spec = load_range(path)
    text = markdown.render(spec, load_index(), {"web": "/root/flag.txt", "cache": "/tmp/flag.txt"})
    assert_snapshot("dmz-redis-scenario.md", text)
    assert "CVE-2017-5638" in text
    assert "github.com/vulhub/vulhub/tree/" in text
    assert "SOSYA{" + "..." + "}" in text
    assert re.search(r"SOSYA\{[0-9a-f]{32}\}", text) is None


def test_scenario_is_deterministic_and_marks_missing_flags() -> None:
    path = gallery.path("dmz-redis")
    assert path is not None
    spec = load_range(path)
    first = markdown.render(spec, load_index(), {"web": "/flag.txt"})
    assert first == markdown.render(spec, load_index(), {"web": "/flag.txt"})
    assert "| cache | internal | cache (6379/tcp) | not placed |" in first


@pytest.mark.parametrize("internet", [True, False])
def test_scenario_says_whether_the_attacker_has_internet(internet: bool) -> None:
    path = gallery.path("dmz-redis")
    assert path is not None
    spec = load_range(path)
    spec = spec.model_copy(
        update={"attacker": spec.attacker.model_copy(update={"internet": internet})}
    )
    text = markdown.render(spec, load_index(), {})
    assert ("has internet access" in text) is internet

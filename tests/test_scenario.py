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
    assert "Hint 3: the spoiler" in text and "Pivot through web" in text
    for flag in record.flags.values():
        assert flag["value"] not in text
        assert flag["value"] not in log.text()
    assert re.search(r"SOSYA\{[0-9a-f]{32}\}", text) is None
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


def _chain_spec():
    from sosya.spec import parse_range

    return parse_range(
        {
            "apiVersion": "sosya/v1",
            "name": "chain",
            "networks": ["dmz", "internal", "vault"],
            "hosts": [
                {
                    "name": "web",
                    "component": "vulhub/struts2/s2-045",
                    "networks": ["dmz", "internal"],
                },
                {
                    "name": "db",
                    "component": "vulhub/redis/4-unacc",
                    "networks": ["internal", "vault"],
                },
                {"name": "core", "component": "vulhub/redis/4-unacc", "networks": ["vault"]},
            ],
            "attacker": {"networks": ["dmz"]},
        }
    )


def test_scenario_gives_the_way_in_for_hosts_behind_a_pivot() -> None:
    text = markdown.render(_chain_spec(), load_index(), {})
    web = text.split("### web")[1].split("### db")[0]
    db = text.split("### db")[1].split("### core")[0]
    core = text.split("### core")[1]
    assert "The way in" not in web  # the attacker reaches it directly
    assert "Pivot through web, which also joins internal." in db
    assert "Pivot through web, which also joins internal; then db, which also joins vault." in core


def test_hints_are_closed_and_in_order() -> None:
    text = markdown.render(_chain_spec(), load_index(), {})
    assert "<details open" not in text
    section = text.split("### db")[1].split("### core")[0]
    order = ["The way in", "Hint 1: what runs here", "Hint 2: the kind", "Hint 3: the spoiler"]
    positions = [section.index(title) for title in order]
    assert positions == sorted(positions)


def test_hint_1_and_2_never_name_a_cve_or_the_title() -> None:
    cve = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    for entry in load_index().entries:
        first = markdown.product_hint(entry, ["web (8080/tcp)"])
        second = markdown.class_hint(entry)
        for hint in (first, second):
            assert cve.search(hint) is None, entry.id
            assert entry.title not in hint, entry.id
        assert entry.product in first


def test_class_hint_falls_back_when_the_catalog_has_no_class() -> None:
    entry = load_index().get("vulhub/struts2/s2-045")
    assert entry is not None
    only_kind = entry.model_copy(update={"tags": ["Framework"]})
    assert markdown.class_hint(only_kind) == markdown.NO_CLASS
    assert "remote code execution" in markdown.class_hint(entry)


def test_the_spoiler_holds_the_title_cves_and_vulhub_link() -> None:
    text = markdown.render(_chain_spec(), load_index(), {})
    spoiler = text.split("Hint 3: the spoiler")[1].split("</details>")[0]
    assert "CVE-2017-5638" in spoiler and "S2-045" in spoiler
    assert "vulhub/tree/" in spoiler
    before = text.split("Hint 3: the spoiler")[0]
    assert "CVE-2017-5638" not in before


# --- no spoilers outside hint 3 --------------------------------------------------------------

_HINT_3 = re.compile(r"<details><summary>Hint 3: the spoiler</summary>.*?</details>", re.DOTALL)


def _outside_hint_3(text: str) -> str:
    assert "Hint 3: the spoiler" in text
    return _HINT_3.sub("", text)


def _assert_no_spoilers(text: str, sentence: str = "") -> None:
    from sosya import advisories

    outside = advisories.find(_outside_hint_3(text))
    assert outside <= advisories.find(sentence), sorted(outside)


@pytest.mark.parametrize("name", gallery.names())
def test_gallery_scenarios_name_no_advisory_outside_hint_3(name: str) -> None:
    path = gallery.path(name)
    assert path is not None
    spec = load_range(path)
    text = markdown.render(spec, load_index(), {h.name: "/flag.txt" for h in spec.hosts})
    _assert_no_spoilers(text)


def _planned(sentence: str, answers: list[dict[str, Any]]):
    from test_planner import FakeLLM, plan

    from sosya.catalog.loader import load_services
    from sosya.planner import Candidate, Planner

    index = load_index()
    found = [Candidate(index.get(i)) for i in ("vulhub/struts2/s2-045", "vulhub/redis/4-unacc")]
    p = Planner(
        FakeLLM(*(plan(**a) for a in answers)),
        index,
        host_platform="linux/amd64",
        services_of=load_services,
    )
    conversation = p.start(sentence, found)
    draft = p.draft(conversation)
    while draft.errors:
        draft = p.repair(conversation, [str(issue) for issue in draft.errors])
    assert draft.spec is not None
    return draft.spec, index


def test_a_planned_scenario_names_no_advisory_outside_hint_3() -> None:
    sentence = "Struts2 in a DMZ, passwordless Redis inside"
    spoiled = {
        "name": "struts2-cve-2017-5638",
        "description": "Struts2 with CVE-2017-5638 and Redis",
        "objectives": ["Exploit S2-045 on web"],
    }
    spec, index = _planned(sentence, [spoiled, {"name": "ignored"}])
    assert spec.name == "struts2"
    text = markdown.render(spec, index, {})
    _assert_no_spoilers(text, sentence)
    assert "CVE-2017-5638" in text  # still there, in hint 3


def test_a_cve_from_the_sentence_may_stay_outside_hint_3() -> None:
    sentence = "A lab with CVE-2017-5638 in a DMZ and Redis inside"
    named = {"name": "cve-2017-5638-lab", "description": "Struts2 with CVE-2017-5638"}
    spec, index = _planned(sentence, [named])
    text = markdown.render(spec, index, {})
    assert "CVE-2017-5638" in _outside_hint_3(text)
    _assert_no_spoilers(text, sentence)

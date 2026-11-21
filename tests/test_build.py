import json
from pathlib import Path
from typing import Any

import pytest
from test_planner import FakeLLM, plan
from test_runtime import FakeDocker, container, done

from sosya import build as build_module
from sosya import runtime
from sosya.build import build, unique_name
from sosya.catalog.loader import load_index
from sosya.llm.base import RefusalError
from sosya.runtime import HostEnvironmentError, RangeError, classify
from sosya.runtime import state as state_store
from sosya.runtime.docker import Docker
from sosya.validate import Check

QUERIES = {"queries": ["struts2", "redis"]}
SENTENCE = "Struts2 in a DMZ, passwordless Redis inside"
GOOD = [Check("reach", "web:8080", True, "reachable", host="web")]
BAD = [Check("reach", "web:8080", False, "no answer within 90s", host="web")]


class Fakes:
    def __init__(
        self,
        tmp_path: Path,
        *,
        checks: list[list[Check]] | None = None,
        up_errors: list[Exception | None] | None = None,
    ) -> None:
        self.workspace = runtime.Workspace(tmp_path / ".sosya")
        self.ranges = tmp_path / "ranges"
        self.docker_fake = FakeDocker()
        self.docker = Docker(runner=self.docker_fake)
        self.checks = list(checks or [GOOD])
        self.up_errors = list(up_errors or [])
        self.ups: list[Path] = []
        self.downs: list[str] = []
        self.phases: list[tuple[str, str]] = []
        self.reports: list[tuple[str, str]] = []
        self.containers_on_up: list[dict[str, Any]] = []

    def up(self, path: Path, *, report, confirm, allow_privileged, workspace, docker):
        self.ups.append(path)
        self.docker_fake.containers = list(self.containers_on_up)
        spec_name = path.parent.parent.parent.name
        compose = workspace.compose_file(spec_name)
        compose.parent.mkdir(parents=True, exist_ok=True)
        compose.write_text("services: {}\n")
        error = self.up_errors.pop(0) if self.up_errors else None
        if error is not None:
            raise error
        workspace.scenario_file(spec_name).write_text("# scenario\n")
        record = state_store.RangeState(
            spec_name, f"sosya-{spec_name}", str(compose), str(path), "t"
        )
        state_store.record(workspace.root, record)
        return record

    def down(self, name: str, *, report, workspace, docker) -> None:
        self.downs.append(name)
        self.docker_fake.containers = []
        runtime._remove_range_dir(workspace.range_dir(name), docker)

    def check(self, name: str, *, workspace, docker) -> list[Check]:
        return self.checks.pop(0)

    def run(self, llm: FakeLLM, **kwargs: Any):
        return build(
            SENTENCE,
            llm,
            report=lambda level, text: self.reports.append((level, text)),
            phase=lambda name, text: self.phases.append((name, text)),
            workspace=self.workspace,
            docker=self.docker,
            index=load_index(),
            host_platform="linux/amd64",
            ranges=self.ranges,
            up=self.up,
            down=self.down,
            check=self.check,
            **kwargs,
        )


def test_green_on_the_first_attempt(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path)
    result = fakes.run(FakeLLM(QUERIES, plan()))
    assert result.outcome == "green", result.message
    assert [a.result for a in result.attempts] == ["green"]
    assert [name for name, _ in fakes.phases] == ["queries", "candidates", "plan", "up", "validate"]
    assert result.range_file == fakes.ranges / "dmz-redis" / "range.yaml"
    assert "flag" not in result.range_file.read_text()
    assert (fakes.ranges / "dmz-redis" / "SCENARIO.md").read_text() == "# scenario\n"
    record = state_store.load(fakes.workspace.root)["dmz-redis"]
    assert record.source == str(result.range_file.resolve())
    assert fakes.downs == []
    for phase in ("queries", "candidates", "plan", "up", "validate", "total"):
        assert phase in result.phases


def test_a_static_problem_is_repaired(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path)
    llm = FakeLLM(QUERIES, plan(networks=["dmz", "internal", "unused"]), plan())
    result = fakes.run(llm)
    assert result.outcome == "green"
    assert [a.result for a in result.attempts] == ["static", "green"]
    saved = fakes.workspace.attempts_dir("dmz-redis") / "1"
    issues = json.loads((saved / "issues.json").read_text())
    assert any("not used" in line for line in issues["static"])
    assert "not used" in llm.calls[-1]["messages"][-1].content
    assert len(fakes.ups) == 1  # nothing starts before the plan is valid


def test_a_failed_check_is_repaired_with_logs(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path, checks=[BAD, GOOD])
    fakes.containers_on_up = [container("web"), container("cache")]
    fakes.docker_fake.on(lambda a: "logs" in a, lambda a: done("line 1\nTomcat failed to start"))
    llm = FakeLLM(QUERIES, plan(), plan())
    result = fakes.run(llm)
    assert result.outcome == "green"
    assert [a.result for a in result.attempts] == ["live", "green"]
    assert fakes.downs == ["dmz-redis"]
    saved = fakes.workspace.attempts_dir("dmz-redis") / "1"
    assert "Tomcat failed to start" in (saved / "logs.txt").read_text()
    assert (saved / "docker-compose.yml").is_file()
    assert (saved / "range.yaml").is_file()
    repair = llm.calls[-1]["messages"][-1].content
    assert "live check failed: reach web:8080" in repair
    assert "Tomcat failed to start" in repair
    logs = fakes.docker_fake.commands("compose")
    assert logs and logs[0][5:] == ["logs", "--no-color", "--tail", "30", "web"]


def test_warnings_never_go_to_the_llm(tmp_path: Path) -> None:
    warning = Check("attacker", "internet access", False, "failed", level="warning")
    fakes = Fakes(tmp_path, checks=[[*GOOD, warning]])
    result = fakes.run(FakeLLM(QUERIES, plan()))
    assert result.outcome == "green"


def test_three_attempts_at_most(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path, checks=[BAD, BAD, BAD])
    result = fakes.run(FakeLLM(QUERIES, plan(), plan(), plan()))
    assert result.outcome == "failed"
    assert len(result.attempts) == 3
    assert fakes.downs == ["dmz-redis"] * 3
    assert sorted(p.name for p in fakes.workspace.attempts_dir("dmz-redis").iterdir()) == [
        "1",
        "2",
        "3",
    ]


def test_a_missing_image_is_repaired(tmp_path: Path) -> None:
    error = classify("manifest unknown")("could not pull vulhub/x:1:\nmanifest unknown")
    fakes = Fakes(tmp_path, up_errors=[error])
    result = fakes.run(FakeLLM(QUERIES, plan(), plan()))
    assert result.outcome == "green"
    assert [a.result for a in result.attempts] == ["live", "green"]


@pytest.mark.parametrize(
    "stderr",
    [
        "toomanyrequests: You have reached your pull rate limit",
        "write /var/lib/docker/tmp: no space left on device",
        "dial tcp: lookup registry-1.docker.io: Temporary failure in name resolution",
    ],
)
def test_machine_problems_stop_without_repair(tmp_path: Path, stderr: str) -> None:
    fakes = Fakes(tmp_path, up_errors=[classify(stderr)(f"could not pull x:\n{stderr}")])
    llm = FakeLLM(QUERIES, plan())
    result = fakes.run(llm)
    assert result.outcome == "environment"
    assert len(llm.calls) == 2  # queries and one draft: no repair
    assert fakes.downs == ["dmz-redis"]
    assert (fakes.workspace.attempts_dir("dmz-redis") / "1" / "issues.json").is_file()


def test_refusals_stop_the_build(tmp_path: Path) -> None:
    class Refusing(FakeLLM):
        def complete_json(self, **kwargs: Any):
            if kwargs["schema_name"] == "range_plan":
                raise RefusalError("the model declined to plan this range", "cyber")
            return super().complete_json(**kwargs)

    result = Fakes(tmp_path).run(Refusing(QUERIES))
    assert result.outcome == "refused"
    assert "declined" in result.message


def test_dangerous_plans_stop_without_the_flag(tmp_path: Path) -> None:
    hosts = [
        {
            "name": "dock",
            "component": "vulhub/docker/unauthorized-rce",
            "networks": ["dmz"],
            "service": None,
        }
    ]
    fakes = Fakes(tmp_path)
    llm = FakeLLM({"queries": ["docker"]}, plan(networks=["dmz"], hosts=hosts))
    result = build(
        "the docker/unauthorized-rce lab",
        llm,
        report=lambda level, text: None,
        phase=lambda n, t: None,
        workspace=fakes.workspace,
        docker=fakes.docker,
        index=load_index(),
        host_platform="linux/amd64",
        ranges=fakes.ranges,
        up=fakes.up,
        down=fakes.down,
        check=fakes.check,
    )
    assert result.outcome == "dangerous"
    assert "--allow-privileged" in result.message
    assert result.dangerous and fakes.ups == []


def test_a_declined_plan_starts_nothing(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path)
    result = fakes.run(FakeLLM(QUERIES, plan()), confirm_plan=lambda spec, r: False)
    assert result.outcome == "cancelled" and fakes.ups == []


def test_an_existing_name_gets_a_suffix(tmp_path: Path) -> None:
    fakes = Fakes(tmp_path)
    (fakes.ranges / "dmz-redis").mkdir(parents=True)
    result = fakes.run(FakeLLM(QUERIES, plan()))
    assert result.outcome == "green"
    assert result.name == "dmz-redis-2" and result.renamed_from == "dmz-redis"
    assert result.range_file == fakes.ranges / "dmz-redis-2" / "range.yaml"
    assert ("warn", "a range named dmz-redis exists: this one is dmz-redis-2") in fakes.reports


def test_unique_name_respects_the_length_limit(tmp_path: Path) -> None:
    workspace = runtime.Workspace(tmp_path / ".sosya")
    ranges = tmp_path / "ranges"
    long = "a" * 40
    (ranges / long).mkdir(parents=True)
    name = unique_name(long, workspace=workspace, docker=Docker(runner=FakeDocker()), ranges=ranges)
    assert name == "a" * 38 + "-2"


@pytest.mark.parametrize(
    ("stderr", "kind"),
    [
        ("toomanyrequests: rate limit", HostEnvironmentError),
        ("no space left on device", HostEnvironmentError),
        ("all predefined address pools have been fully subnetted", HostEnvironmentError),
        ("manifest unknown", RangeError),
        ("pull access denied for vulhub/x, repository does not exist", RangeError),
        ("Error response from daemon: manifest for vulhub/x:1 not found", RangeError),
        ("container web exited (1)", RangeError),
    ],
)
def test_classify(stderr: str, kind: type) -> None:
    assert classify(stderr) is kind


def test_down_keeps_the_attempts(tmp_path: Path) -> None:
    workspace = runtime.Workspace(tmp_path / ".sosya")
    attempts = workspace.attempts_dir("lab") / "1"
    attempts.mkdir(parents=True)
    (attempts / "range.yaml").write_text("x")
    workspace.compose_file("lab").write_text("services: {}")
    (workspace.files_dir("lab") / "web").mkdir(parents=True)
    runtime._remove_range_dir(workspace.range_dir("lab"), Docker(runner=FakeDocker()))
    assert sorted(p.name for p in workspace.range_dir("lab").iterdir()) == ["attempts"]
    assert (attempts / "range.yaml").is_file()


def test_build_module_has_three_attempts() -> None:
    assert build_module.MAX_ATTEMPTS == 3

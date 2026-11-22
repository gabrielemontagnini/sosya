import json
from collections.abc import Sequence
from typing import Any

import pytest
from factories import entry, index, services_of

from sosya.catalog.models import CatalogIndex, DangerReason
from sosya.llm.base import Completion, Message
from sosya.planner import Candidate, Planner
from sosya.planner.candidates import candidates
from sosya.planner.prompt import PLAN_SYSTEM, QUERY_SYSTEM
from sosya.planner.schema import PLAN_SCHEMA, QUERY_SCHEMA


class FakeLLM:
    provider = "fake"
    line = "test"
    model = "test-sonnet-1"

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        *,
        system: str,
        messages: Sequence[Message],
        schema: dict,
        schema_name: str,
        max_tokens: int = 16000,
        effort: str | None = None,
    ) -> Completion:
        self.calls.append(
            {"system": system, "messages": list(messages), "schema": schema, "effort": effort}
        )
        return Completion(data=self.answers.pop(0), stop_reason="end_turn", elapsed=0.1)


def plan(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "dmz-redis",
        "description": "Struts2 in a DMZ, Redis inside",
        "networks": ["dmz", "internal"],
        "hosts": [
            {
                "name": "web",
                "component": "vulhub/struts2/s2-045",
                "networks": ["dmz", "internal"],
                "service": None,
            },
            {
                "name": "cache",
                "component": "vulhub/redis/4-unacc",
                "networks": ["internal"],
                "service": None,
            },
        ],
        "attacker": {"networks": ["dmz"], "internet": True},
        "objectives": ["Get a shell on web"],
    }
    data.update(overrides)
    return data


def planner(llm: FakeLLM, catalog: CatalogIndex | None = None, platform: str = "linux/amd64"):
    return Planner(llm, catalog or index(), host_platform=platform, services_of=services_of)


# --- candidates -----------------------------------------------------------------------------


def ids(found) -> list[str]:
    return [c.entry.id for c in found]


def test_dangerous_entries_only_when_the_sentence_names_them() -> None:
    catalog = index()
    vague = candidates(catalog, "a docker lab", ["docker", "unauthorized-rce"], host_platform=None)
    assert "vulhub/docker/unauthorized-rce" not in ids(vague)
    named = candidates(catalog, "lab with docker/unauthorized-rce", [], host_platform=None)
    assert "vulhub/docker/unauthorized-rce" in ids(named)


def test_dangerous_entries_named_by_cve_in_the_sentence() -> None:
    catalog = CatalogIndex(
        vulhub_commit="0" * 40,
        entries=[
            entry(
                "vulhub/x/CVE-2025-1974",
                ["x"],
                dangerous=[DangerReason(service="x", reason="privileged")],
            ).model_copy(update={"cves": ["CVE-2025-1974"]})
        ],
    )
    assert ids(candidates(catalog, "ingress lab", ["CVE-2025-1974"], host_platform=None)) == []
    assert ids(candidates(catalog, "lab for cve-2025-1974", [], host_platform=None)) == [
        "vulhub/x/CVE-2025-1974"
    ]


def test_platforms_exclude_or_mark_emulation() -> None:
    catalog = index()
    on_amd64 = candidates(catalog, "arm only app", ["arm", "struts2"], host_platform="linux/amd64")
    assert "vulhub/arm/only" not in ids(on_amd64)
    on_arm = candidates(catalog, "struts2 app", [], host_platform="linux/arm64")
    (struts,) = [c for c in on_arm if c.entry.id == "vulhub/struts2/s2-045"]
    assert struts.emulated
    arm = candidates(catalog, "arm only", [], host_platform="linux/arm64")
    assert any(c.entry.id == "vulhub/arm/only" and not c.emulated for c in arm)


def test_unknown_platforms_are_excluded() -> None:
    assert "vulhub/broken/image" not in ids(
        candidates(index(), "broken image", [], host_platform=None)
    )


def test_queries_widen_the_search() -> None:
    found = candidates(index(), "a web lab with a cache", ["struts2", "redis"], host_platform=None)
    assert {"vulhub/struts2/s2-045", "vulhub/redis/4-unacc"} <= set(ids(found))


# --- queries --------------------------------------------------------------------------------


def test_derive_queries_at_low_effort() -> None:
    llm = FakeLLM({"queries": [" struts2 ", "redis", "struts2", ""]})
    assert planner(llm).derive_queries("Struts2 and Redis") == ["struts2", "redis"]
    (call,) = llm.calls
    assert call["effort"] == "low"
    assert call["system"] == QUERY_SYSTEM
    assert call["schema"] == QUERY_SCHEMA


def test_derive_queries_tolerates_a_bad_answer() -> None:
    assert planner(FakeLLM({"nope": 1})).derive_queries("x") == []


# --- drafts ---------------------------------------------------------------------------------


def start(p: Planner, sentence: str = "Struts2 in a DMZ, Redis inside"):
    return p.start(sentence, p.candidates(sentence, ["struts2", "redis"]))


def test_a_good_draft_becomes_a_spec() -> None:
    llm = FakeLLM(plan())
    p = planner(llm)
    draft = p.draft(start(p))
    assert draft.errors == []
    assert draft.spec is not None and draft.spec.name == "dmz-redis"
    assert all(host.flag is None for host in draft.spec.hosts)
    (call,) = llm.calls
    assert call["system"] == PLAN_SYSTEM
    assert "vulhub/struts2/s2-045" in call["messages"][0].content


def test_the_plan_schema_never_depends_on_the_candidates() -> None:
    llm = FakeLLM(plan(), plan())
    p = planner(llm)
    p.draft(p.start("struts2", p.candidates("struts2", [])))
    p.draft(p.start("wordpress", p.candidates("wordpress", [])))
    first, second = (json.dumps(c["schema"], sort_keys=True) for c in llm.calls)
    assert first == second == json.dumps(PLAN_SCHEMA, sort_keys=True)
    assert "enum" not in first
    assert "flag" not in PLAN_SCHEMA["$defs"]["DraftHost"]["properties"]


def test_a_component_outside_the_candidates_is_an_issue() -> None:
    hosts = [
        {
            "name": "web",
            "component": "vulhub/wordpress/pwnscriptum",
            "networks": ["dmz"],
            "service": None,
        }
    ]
    p = planner(FakeLLM(plan(networks=["dmz"], hosts=hosts)))
    draft = p.draft(start(p))
    assert draft.spec is None
    assert any("not one of the candidate ids" in str(issue) for issue in draft.errors)


def test_schema_problems_become_issues() -> None:
    bad = plan(networks=["dmz", "internal", "unused"])
    p = planner(FakeLLM(bad))
    draft = p.draft(start(p))
    assert draft.spec is None
    assert any("not used" in issue.message for issue in draft.errors)


def test_shape_problems_become_issues() -> None:
    p = planner(FakeLLM({"name": "x"}))
    draft = p.draft(start(p))
    assert draft.spec is None and draft.errors


def test_repair_keeps_the_conversation_and_the_name() -> None:
    llm = FakeLLM(plan(networks=["dmz", "internal", "unused"]), plan(name="other-name"))
    p = planner(llm)
    conversation = start(p)
    first = p.draft(conversation)
    second = p.repair(conversation, [str(issue) for issue in first.errors])
    assert second.errors == []
    assert second.spec is not None and second.spec.name == "dmz-redis"
    messages = llm.calls[1]["messages"]
    assert [m.role for m in messages] == ["user", "assistant", "user"]
    assert "not used" in messages[2].content
    assert messages[:2] == llm.calls[0]["messages"] + [messages[1]]


def test_dangerous_entries_are_reported_not_repaired() -> None:
    hosts = [
        {
            "name": "dock",
            "component": "vulhub/docker/unauthorized-rce",
            "networks": ["dmz"],
            "service": None,
        }
    ]
    p = planner(FakeLLM(plan(networks=["dmz"], hosts=hosts)))
    sentence = "the docker/unauthorized-rce lab"
    draft = p.draft(p.start(sentence, p.candidates(sentence, [])))
    assert draft.errors == []
    assert draft.dangerous and "privileged" in draft.dangerous[0].message


@pytest.mark.parametrize("schema", [QUERY_SCHEMA, PLAN_SCHEMA])
def test_schemas_are_strict(schema: dict) -> None:
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)


def test_the_plan_request_marks_entries_with_local_files() -> None:
    from sosya.catalog.loader import load_index as real_index
    from sosya.planner import prompt

    catalog = real_index()
    files = next(e for e in catalog.entries if not e.image_only)
    image = next(e for e in catalog.entries if e.image_only)
    text = prompt.plan_request("x", [Candidate(files), Candidate(image)])
    first, second = text.splitlines()[-2:]
    assert first.startswith(f"- {files.id}") and "[local files]" in first
    assert second.startswith(f"- {image.id}") and "[local files]" not in second
    assert "[local files]" in prompt.PLAN_SYSTEM


def test_queries_use_low_effort_or_none_when_chosen() -> None:
    llm = FakeLLM({"queries": ["x"]}, {"queries": ["y"]}, {"queries": ["z"]})
    planner(llm).derive_queries("a lab")
    Planner(llm, index(), host_platform=None, effort="none").derive_queries("a lab")
    llm.effort = "none"  # the adapter's own effort, from SOSYA_EFFORT
    planner(llm).derive_queries("a lab")
    assert [call["effort"] for call in llm.calls] == ["low", "none", "none"]


def test_the_planner_forwards_adapter_warnings() -> None:
    from sosya.llm.base import Completion

    class Warning(FakeLLM):
        def complete_json(self, **kwargs: Any) -> Completion:
            result = super().complete_json(**kwargs)
            return Completion(result.data, result.stop_reason, result.elapsed, warnings=["cut"])

    seen: list[str] = []
    found = Planner(
        Warning({"queries": ["x"]}), index(), host_platform=None, warn=seen.append
    ).derive_queries("a lab")
    assert found == ["x"] and seen == ["cut"]

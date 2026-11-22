"""The planner: from a sentence to a checked `RangeSpec`, through the LLM.

1. `derive_queries`: the LLM turns the sentence into catalog keywords (at low effort, or none
   when the user chose none).
2. `candidates`: a lexical search with Reciprocal Rank Fusion picks at most 25 entries.
3. `draft`: the LLM writes a lab from those candidates; Pydantic, the range schema,
   `check_catalog` and a "candidates only" check turn every mistake into an `Issue`.
4. `repair`: the issues (and, from the build, live failures) go back to the LLM in the same
   conversation, which only grows, so the provider's prompt cache keeps working.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from sosya.catalog.loader import load_services
from sosya.catalog.models import CatalogIndex
from sosya.llm.base import LLM, Completion, Message
from sosya.llm.http import dumps
from sosya.planner import prompt
from sosya.planner.candidates import Candidate, candidates
from sosya.planner.schema import MAX_QUERIES, PLAN_SCHEMA, QUERY_SCHEMA, PlanDraft, QueryPlan
from sosya.spec import Issue, RangeSpec, SpecError, check_catalog, issues_from, parse_range

QUERY_EFFORT = "low"


@dataclass
class Conversation:
    sentence: str
    candidates: list[Candidate]
    messages: list[Message] = field(default_factory=list)
    name: str | None = None
    """Fixed by the first draft: later drafts keep it."""
    extra_ids: set[str] = field(default_factory=set)
    """Components the user chose by editing the plan: repairs may keep them."""
    edited: RangeSpec | None = None
    """A range the user edited, not yet shown to the LLM: the next repair request carries it."""

    @property
    def ids(self) -> set[str]:
        return {c.entry.id for c in self.candidates} | self.extra_ids

    def adopt(self, spec: RangeSpec) -> None:
        """The user edited the plan: repairs start from `spec`, not from the last draft."""
        self.name = spec.name
        self.extra_ids |= {host.component for host in spec.hosts}
        self.edited = spec


@dataclass(frozen=True)
class Draft:
    spec: RangeSpec | None
    issues: list[Issue]
    elapsed: float
    data: Any = None

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.level == "error"]

    @property
    def dangerous(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning" and "host-level" in i.message]


def _validation_issues(exc: ValidationError) -> list[Issue]:
    issues = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"])
        issues.append(Issue("error", f"{where}: {error['msg']}" if where else error["msg"]))
    return issues


class Planner:
    def __init__(
        self,
        llm: LLM,
        index: CatalogIndex,
        *,
        host_platform: str | None,
        effort: str | None = None,
        services_of: Callable[[str], dict[str, Any]] = load_services,
        warn: Callable[[str], None] = lambda text: None,
    ) -> None:
        self.llm = llm
        self.warn = warn
        self.index = index
        self.host_platform = host_platform
        self.effort = effort
        self.services_of = services_of

    def _forward(self, result: Completion) -> Completion:
        for warning in result.warnings:
            self.warn(warning)
        return result

    @property
    def query_effort(self) -> str:
        chosen = self.effort or getattr(self.llm, "effort", None)
        return "none" if chosen == "none" else QUERY_EFFORT

    def derive_queries(self, sentence: str) -> list[str]:
        result = self.llm.complete_json(
            system=prompt.QUERY_SYSTEM,
            messages=[Message("user", sentence)],
            schema=QUERY_SCHEMA,
            schema_name="catalog_queries",
            max_tokens=4000,
            effort=self.query_effort,
        )
        self._forward(result)
        try:
            plan = QueryPlan.model_validate(result.data)
        except ValidationError:
            return []
        cleaned = [q.strip() for q in plan.queries if q.strip()]
        return list(dict.fromkeys(cleaned))[:MAX_QUERIES]

    def candidates(self, sentence: str, queries: Sequence[str]) -> list[Candidate]:
        return candidates(self.index, sentence, queries, host_platform=self.host_platform)

    def start(self, sentence: str, found: list[Candidate]) -> Conversation:
        conversation = Conversation(sentence=sentence, candidates=found)
        conversation.messages.append(Message("user", prompt.plan_request(sentence, found)))
        return conversation

    def draft(self, conversation: Conversation) -> Draft:
        result = self.llm.complete_json(
            system=prompt.PLAN_SYSTEM,
            messages=conversation.messages,
            schema=PLAN_SCHEMA,
            schema_name="range_plan",
            effort=self.effort,
        )
        self._forward(result)
        conversation.messages.append(Message("assistant", dumps(result.data)))
        return Draft(
            *self._check(conversation, result.data), elapsed=result.elapsed, data=result.data
        )

    def _check(self, conversation: Conversation, data: Any) -> tuple[RangeSpec | None, list[Issue]]:
        try:
            plan = PlanDraft.model_validate(data)
        except ValidationError as exc:
            return None, _validation_issues(exc)
        range_data = plan.to_range_data()
        if conversation.name is None:
            conversation.name = plan.name
        else:
            range_data["name"] = conversation.name  # the name stays fixed across attempts
        outside = [
            Issue("error", f"component {h.component} is not one of the candidate ids", h.name)
            for h in plan.hosts
            if h.component not in conversation.ids
        ]
        try:
            spec = parse_range(range_data, "the lab")
        except SpecError as exc:
            return None, outside + issues_from(exc)
        if outside:
            return None, outside
        issues = check_catalog(
            spec,
            self.index,
            host_platform=self.host_platform,
            allow_privileged=True,  # the build stops on dangerous entries; they are not repaired
            services_of=self.services_of,
        )
        return spec, issues

    def repair(self, conversation: Conversation, problems: Sequence[str]) -> Draft:
        edited, conversation.edited = conversation.edited, None
        request = prompt.repair_request(problems, edited=edited)
        conversation.messages.append(Message("user", request))
        return self.draft(conversation)


__all__ = ["Candidate", "Conversation", "Draft", "Planner", "candidates"]

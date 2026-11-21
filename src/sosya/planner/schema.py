"""The two fixed schemas the LLM answers with. They never depend on the request.

`PlanDraft` is not `RangeSpec`: it has no `flag` (flag paths are not the LLM's choice) and no
free-form reasoning field. `to_range_data` turns it into a `range.yaml` mapping, which then goes
through the same validation as a hand-written file.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict

from sosya.llm.schema import strict_schema
from sosya.spec import API_VERSION

MAX_QUERIES = 8


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class QueryPlan(_Model):
    queries: list[str]


class DraftHost(_Model):
    name: str
    component: str
    networks: list[str]
    service: str | None


class DraftAttacker(_Model):
    networks: list[str]
    internet: bool


class PlanDraft(_Model):
    name: str
    description: str
    networks: list[str]
    hosts: list[DraftHost]
    attacker: DraftAttacker
    objectives: list[str]

    def to_range_data(self) -> dict[str, Any]:
        hosts = []
        for host in self.hosts:
            item: dict[str, Any] = {
                "name": host.name,
                "component": host.component,
                "networks": list(host.networks),
            }
            if host.service:
                item["service"] = host.service
            hosts.append(item)
        return {
            "apiVersion": API_VERSION,
            "name": self.name,
            "description": self.description,
            "networks": list(self.networks),
            "hosts": hosts,
            "attacker": {
                "networks": list(self.attacker.networks),
                "internet": self.attacker.internet,
            },
            "objectives": list(self.objectives),
        }


QUERY_SCHEMA = strict_schema(QueryPlan)
PLAN_SCHEMA = strict_schema(PlanDraft)

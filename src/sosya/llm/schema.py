"""Turn a Pydantic JSON schema into the strict subset that structured output accepts.

Every object gets `additionalProperties: false` and lists all its properties as required.
Constraints that the providers do not support (lengths, bounds, patterns, defaults) are removed
here; Pydantic checks them again on the parsed result.
"""

import copy
from typing import Any

from pydantic import BaseModel

_DROPPED = frozenset(
    {
        "default",
        "title",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "pattern",
    }
)
_FORMATS = frozenset(
    {"date-time", "time", "date", "duration", "email", "hostname", "uri", "ipv4", "ipv6", "uuid"}
)


def _clean(node: Any) -> Any:
    if isinstance(node, list):
        return [_clean(item) for item in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in _DROPPED:
            continue
        if key == "format" and value not in _FORMATS:
            continue
        if key in ("properties", "$defs"):
            # Keys here are names chosen by the schema, not keywords: keep them all.
            out[key] = {name: _clean(sub) for name, sub in value.items()}
        else:
            out[key] = _clean(value)
    if out.get("type") == "object" or "properties" in out:
        out["additionalProperties"] = False
        out["required"] = list(out.get("properties", {}))
    return out


def strict_schema(source: type[BaseModel] | dict[str, Any]) -> dict[str, Any]:
    raw = (
        source.model_json_schema(by_alias=True)
        if isinstance(source, type)
        else copy.deepcopy(source)
    )
    return _clean(raw)

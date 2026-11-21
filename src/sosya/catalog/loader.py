"""Load the catalog data shipped inside the package, without any network access."""

import copy
import json
from functools import cache
from importlib import resources
from typing import Any

from sosya.catalog.models import CatalogIndex

INDEX_RESOURCE = "data/index.json"
COMPOSE_RESOURCE = "data/compose.json"


@cache
def load_index() -> CatalogIndex:
    """Return the packaged index. The result is cached for the life of the process."""
    text = resources.files("sosya.catalog").joinpath(INDEX_RESOURCE).read_text(encoding="utf-8")
    return CatalogIndex.model_validate_json(text)


@cache
def _all_services() -> dict[str, dict[str, Any]]:
    text = resources.files("sosya.catalog").joinpath(COMPOSE_RESOURCE).read_text(encoding="utf-8")
    return json.loads(text)


def load_services(entry_id: str) -> dict[str, Any]:
    """The Vulhub `services:` mapping of one environment. The caller gets its own copy."""
    try:
        return copy.deepcopy(_all_services()[entry_id])
    except KeyError:
        raise KeyError(f"no service definitions for {entry_id}") from None

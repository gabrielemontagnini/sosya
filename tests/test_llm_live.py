"""Calls to a real LLM: `~/.local/bin/with-llm-key uv run pytest -m llm`."""

import pytest

from sosya import llm
from sosya.catalog.loader import load_index
from sosya.planner import Planner

pytestmark = pytest.mark.llm


def test_a_real_model_derives_catalog_queries() -> None:
    planner = Planner(llm.select(), load_index(), host_platform="linux/amd64")
    queries = planner.derive_queries("A Jenkins server with a remote code execution bug")
    assert queries
    assert any("jenkins" in query.lower() for query in queries)

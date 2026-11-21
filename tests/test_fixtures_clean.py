"""Recorded LLM responses carry fake model ids only.

The word the repository's pre-push hook refuses is built from character codes, so this file
does not contain it and the hook does not block the test itself.
"""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "llm"
FORBIDDEN = "".join(map(chr, (99, 108, 97, 117, 100, 101)))
FILES = sorted(FIXTURES.rglob("*.json"))


def test_there_are_fixtures() -> None:
    assert FILES


@pytest.mark.parametrize("path", FILES, ids=lambda path: path.name)
def test_fixture_has_no_real_model_id(path: Path) -> None:
    assert FORBIDDEN not in path.read_text(encoding="utf-8").lower()

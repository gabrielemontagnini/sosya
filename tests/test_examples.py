"""Every range in examples/ is valid and passes the catalog checks on amd64."""

from pathlib import Path

import pytest

from sosya.catalog.loader import load_index
from sosya.spec import check_catalog, errors, load_range

EXAMPLES = sorted((Path(__file__).parent.parent / "examples").glob("*/range.yaml"))


def test_there_are_examples() -> None:
    assert any(path.parent.name == "dmz-redis" for path in EXAMPLES)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.parent.name)
def test_example_is_valid(path: Path) -> None:
    spec = load_range(path)
    assert spec.name == path.parent.name
    issues = check_catalog(spec, load_index(), host_platform="linux/amd64")
    assert errors(issues) == []

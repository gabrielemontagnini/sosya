"""Load the catalog index shipped inside the package, without any network access."""

from functools import cache
from importlib import resources

from sosya.catalog.models import CatalogIndex

INDEX_RESOURCE = "data/index.json"


@cache
def load_index() -> CatalogIndex:
    """Return the packaged index. The result is cached for the life of the process."""
    text = resources.files("sosya.catalog").joinpath(INDEX_RESOURCE).read_text(encoding="utf-8")
    return CatalogIndex.model_validate_json(text)

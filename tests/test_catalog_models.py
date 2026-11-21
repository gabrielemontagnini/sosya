import pytest
from pydantic import ValidationError

from sosya.catalog.models import CatalogIndex, DangerReason, Entry, LocalFile, Service


def _entry(**changes) -> Entry:
    fields = {
        "id": "vulhub/app/cve",
        "path": "app/cve",
        "product": "App",
        "product_dir": "app",
        "title": "App flaw",
        "services": [Service(name="web", image="vulhub/app:1", platforms=["linux/amd64"])],
    }
    return Entry(**(fields | changes))


def test_image_only_without_local_files() -> None:
    assert _entry().image_only
    files = [LocalFile(service="web", kind="bind", source="./www")]
    assert not _entry(local_files=files).image_only


def test_dangerous_flag_follows_reasons() -> None:
    assert not _entry().is_dangerous
    assert _entry(dangerous=[DangerReason(service="web", reason="privileged")]).is_dangerous


def test_entry_platforms_are_the_intersection_of_services() -> None:
    services = [
        Service(name="web", platforms=["linux/amd64", "linux/arm64"]),
        Service(name="db", platforms=["linux/amd64"]),
    ]
    assert _entry(services=services).platforms == ["linux/amd64"]


def test_entry_platforms_unknown_if_any_service_unknown() -> None:
    services = [Service(name="web", platforms=["linux/amd64"]), Service(name="db")]
    assert _entry(services=services).platforms is None


def test_models_are_frozen_and_strict() -> None:
    entry = _entry()
    with pytest.raises(ValidationError):
        entry.title = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Service(name="web", unexpected=True)  # type: ignore[call-arg]


def test_index_lookup_by_id() -> None:
    index = CatalogIndex(vulhub_commit="abc", entries=[_entry()])
    assert index.get("vulhub/app/cve") is not None
    assert index.get("vulhub/missing") is None

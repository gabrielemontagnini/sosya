"""Checks on the real index shipped in the package. No network needed."""

import re

import pytest

from sosya.catalog import VULHUB_COMMIT
from sosya.catalog.loader import load_index
from sosya.catalog.models import CatalogIndex

# Counted by the parser on the pinned commit and checked by hand against the compose files.
TOTAL = 334
IMAGE_ONLY = 230
NEED_LOCAL_FILES = 104
MULTI_SERVICE = 88
DANGEROUS = {
    "vulhub/docker/unauthorized-rce": ["privileged"],
    "vulhub/ingress-nginx/CVE-2025-1974": ["privileged"],
}
# Upstream images that cannot be pulled, so their platforms are unknown.
UNKNOWN_PLATFORMS = {
    "vulhub/budibase/CVE-2026-31816",  # minio/minio tag no longer public on Docker Hub
    "vulhub/craftcms/CVE-2025-32432",  # vulhub/craftcms:5.6.16 was never pushed
}
GALLERY = [
    "vulhub/wordpress/pwnscriptum",
    "vulhub/struts2/s2-045",
    "vulhub/redis/4-unacc",
    "vulhub/log4j/CVE-2021-44228",
    "vulhub/grafana/CVE-2021-43798",
    "vulhub/drupal/CVE-2018-7600",
    "vulhub/samba/CVE-2017-7494",
    "vulhub/openssh/CVE-2018-15473",
    "vulhub/jenkins/CVE-2018-1000861",
]
# Published for arm64 only (one manifest, no list), so it cannot run natively on amd64.
ARM64_ONLY = {"vulhub/python/CVE-2024-23334"}
PLATFORM = re.compile(r"^(linux|windows)/[a-z0-9]+(/v[0-9]+)?$")


@pytest.fixture(scope="module")
def index() -> CatalogIndex:
    return load_index()


def test_index_is_cached() -> None:
    assert load_index() is load_index()


def test_index_matches_the_pinned_commit(index: CatalogIndex) -> None:
    assert index.vulhub_commit == VULHUB_COMMIT
    assert len(index.entries) == TOTAL
    ids = [entry.id for entry in index.entries]
    assert len(set(ids)) == TOTAL
    assert ids == sorted(ids)


def test_counts(index: CatalogIndex) -> None:
    assert sum(entry.image_only for entry in index.entries) == IMAGE_ONLY
    assert sum(not entry.image_only for entry in index.entries) == NEED_LOCAL_FILES
    assert sum(len(entry.services) >= 2 for entry in index.entries) == MULTI_SERVICE


def test_dangerous_environments(index: CatalogIndex) -> None:
    found = {e.id: [r.reason for r in e.dangerous] for e in index.entries if e.is_dangerous}
    assert found == DANGEROUS


def test_platforms(index: CatalogIndex) -> None:
    unknown = {entry.id for entry in index.entries if entry.platforms is None}
    assert unknown == UNKNOWN_PLATFORMS
    no_amd64 = {e.id for e in index.entries if e.platforms and "linux/amd64" not in e.platforms}
    assert no_amd64 == ARM64_ONLY
    for entry in index.entries:
        for service in entry.services:
            for item in service.platforms or []:
                assert PLATFORM.match(item), (entry.id, item)


def test_gallery_candidates(index: CatalogIndex) -> None:
    for entry_id in GALLERY:
        entry = index.get(entry_id)
        assert entry is not None, entry_id
        assert entry.platforms == ["linux/amd64"], entry_id
    s2_045 = index.get("vulhub/struts2/s2-045")
    assert s2_045 is not None
    assert s2_045.cves == ["CVE-2017-5638"]
    assert [(p.port, p.protocol) for s in s2_045.services for p in s.ports] == [(8080, "tcp")]


def test_every_entry_is_complete(index: CatalogIndex) -> None:
    for entry in index.entries:
        assert entry.id == f"vulhub/{entry.path}"
        assert entry.title
        assert entry.summary, entry.id
        assert entry.services
        for service in entry.services:
            assert service.image or service.build_context, (entry.id, service.name)
            for port in service.ports:
                assert 0 < port.port < 65536


def test_summaries_carry_no_setup_or_attack_steps(index: CatalogIndex) -> None:
    for entry in index.entries:
        summary = entry.summary.lower()
        for marker in ("docker compose", "docker-compose", "```", "your-ip", "following command"):
            assert marker not in summary, (entry.id, marker)

"""Pydantic models for the catalog index shipped inside the package."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, computed_field

SCHEMA_VERSION = 1


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Port(_Model):
    """A port a service listens on, on the container side."""

    port: int
    protocol: Literal["tcp", "udp"] = "tcp"


class LocalFile(_Model):
    """A file or directory from the Vulhub checkout that a service needs at start time."""

    service: str
    kind: Literal["build", "bind", "env_file"]
    source: str


class DangerReason(_Model):
    """Why a service gets host-level privileges (see docs/architecture.md)."""

    service: str
    reason: str


class Service(_Model):
    name: str
    image: str | None = None
    build_context: str | None = None
    base_images: list[str] = []
    ports: list[Port] = []
    platforms: list[str] | None = None
    """Platforms of `image`, or of the final `FROM` image for a `build:` service.

    `None` means unknown: the image was not found or its base could not be resolved.
    """


class Entry(_Model):
    id: str
    path: str
    product: str
    product_dir: str
    cves: list[str] = []
    title: str
    summary: str = ""
    references: list[str] = []
    tags: list[str] = []
    services: list[Service]
    local_files: list[LocalFile] = []
    dangerous: list[DangerReason] = []

    @computed_field  # type: ignore[prop-decorator]
    @property
    def image_only(self) -> bool:
        return not self.local_files

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_dangerous(self) -> bool:
        return bool(self.dangerous)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def platforms(self) -> list[str] | None:
        """Platforms on which every service can run, or `None` if any is unknown."""
        common: set[str] | None = None
        for service in self.services:
            if service.platforms is None:
                return None
            common = set(service.platforms) if common is None else common & set(service.platforms)
        return sorted(common or ())


class CatalogIndex(_Model):
    schema_version: int = SCHEMA_VERSION
    vulhub_commit: str
    entries: list[Entry]

    def get(self, entry_id: str) -> Entry | None:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

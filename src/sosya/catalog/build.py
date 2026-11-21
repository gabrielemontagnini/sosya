"""Development only: build the catalog index from Vulhub at the pinned commit.

    uv run python -m sosya.catalog.build sync        # sparse clone into .cache/vulhub
    uv run python -m sosya.catalog.build platforms   # image platforms, cached and resumable
    uv run python -m sosya.catalog.build index       # write the packaged catalog data

Run from the repository root. `sosya` itself never imports this module.
"""

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

from sosya.catalog import VULHUB_COMMIT
from sosya.catalog.models import CatalogIndex, Entry
from sosya.catalog.parse import parse_environment, platform_image, with_platforms
from sosya.catalog.platforms import (
    DEFAULT_CACHE,
    CacheEntry,
    cached_platforms,
    detect,
    load_cache,
)
from sosya.catalog.source import DEFAULT_CHECKOUT, head, sync

DATA_DIR = Path("src/sosya/catalog/data")
INDEX_PATH = DATA_DIR / "index.json"
COMPOSE_PATH = DATA_DIR / "compose.json"
LICENSE_PATH = DATA_DIR / "VULHUB-LICENSE"
OK = "[green]ok[/]"
FAIL = "[red]fail[/]"
WARN = "[yellow]warn[/]"

console = Console()


def read_environments(checkout: Path) -> list[Entry]:
    """Parse every environment of `environments.toml`, without platforms."""
    if head(checkout) != VULHUB_COMMIT:
        raise SystemExit(f"{checkout} is not at {VULHUB_COMMIT}: run `build sync` first")
    toml = tomllib.loads((checkout / "environments.toml").read_text(encoding="utf-8"))
    entries = []
    for meta in toml["environment"]:
        directory = checkout / meta["path"]

        def read_file(name: str, directory: Path = directory) -> str | None:
            path = directory / name
            return path.read_text(encoding="utf-8") if path.is_file() else None

        compose = (directory / "docker-compose.yml").read_text(encoding="utf-8")
        readme = read_file("README.md") or ""
        entries.append(parse_environment(meta, compose, readme, read_file))
    return sorted(entries, key=lambda entry: entry.id)


def read_services(checkout: Path, entries: list[Entry]) -> dict[str, dict[str, Any]]:
    """The `services:` mapping of every environment, as Vulhub wrote it (anchors resolved).

    The renderer copies only the keys that `sosya.catalog.rules` allows, so nothing is
    filtered here: the shipped data stays a faithful copy of the pinned commit.
    """
    services = {}
    for entry in entries:
        compose = yaml.safe_load((checkout / entry.path / "docker-compose.yml").read_text("utf-8"))
        services[entry.id] = compose["services"]
    return services


def dump_services(services: dict[str, dict[str, Any]]) -> str:
    # Keys are not sorted: the order of services and of their keys is meaningful.
    return json.dumps(services, indent=1, ensure_ascii=False) + "\n"


def referenced_images(entries: list[Entry]) -> list[str]:
    images = {platform_image(service) for entry in entries for service in entry.services}
    return sorted(image for image in images if image)


def build_index(entries: list[Entry], cache: dict[str, CacheEntry]) -> CatalogIndex:
    lookup = cached_platforms(cache)
    return CatalogIndex(
        vulhub_commit=VULHUB_COMMIT,
        entries=[with_platforms(entry, lookup) for entry in entries],
    )


def dump_index(index: CatalogIndex) -> str:
    data = index.model_dump(mode="json", exclude_computed_fields=True)
    return json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def cmd_sync(args: argparse.Namespace) -> int:
    checkout = sync(args.checkout)
    console.print(f"{OK} Vulhub at {VULHUB_COMMIT[:7]} in {checkout}")
    return 0


def cmd_platforms(args: argparse.Namespace) -> int:
    images = referenced_images(read_environments(args.checkout))
    refresh = "all" if args.refresh_all else "errors" if args.refresh else "missing"

    def show(image: str, entry: CacheEntry) -> None:
        if entry.platforms:
            console.print(f"{OK} {image}: {', '.join(entry.platforms)} [dim]({entry.source})[/]")
        else:
            console.print(f"{WARN} {image}: {entry.error}")

    console.print(f"{len(images)} images referenced, cache {args.cache}")
    report = detect(images, args.cache, refresh=refresh, delay=args.delay, on_result=show)
    console.print(f"{len(report.checked)} checked, {report.skipped} already in the cache")
    if report.not_found:
        console.print(f"{WARN} {len(report.not_found)} not found: {', '.join(report.not_found)}")
    if report.failed:
        console.print(f"{FAIL} {len(report.failed)} failed (retry with --refresh)")
    if report.needs_login:
        console.print(
            f"{FAIL} {len(report.needs_login)} need the registry fallback, which counts against "
            "the Docker Hub pull limit: run `docker login`, then run this again"
        )
    if report.rate_limited:
        console.print(
            f"{FAIL} {report.rate_limited}: {len(report.remaining)} images left. "
            "Progress is saved; run this again later to resume."
        )
    if report.complete:
        console.print(f"{OK} platform cache complete")
        return 0
    return 2


def cmd_index(args: argparse.Namespace) -> int:
    entries = read_environments(args.checkout)
    cache = load_cache(args.cache)
    missing = [image for image in referenced_images(entries) if image not in cache]
    if missing and not args.allow_missing_platforms:
        console.print(f"{FAIL} {len(missing)} images missing from {args.cache}: run `platforms`")
        for image in missing:
            console.print(f"  {image}")
        return 2
    index = build_index(entries, cache)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(dump_index(index), encoding="utf-8")
    console.print(f"{OK} {len(index.entries)} environments written to {args.output}")
    compose_output = args.output.with_name(COMPOSE_PATH.name)
    compose_output.write_text(dump_services(read_services(args.checkout, entries)), "utf-8")
    console.print(f"{OK} service definitions written to {compose_output}")
    license_file = args.checkout / "LICENSE"
    if not license_file.is_file():
        console.print(f"{FAIL} {license_file} is missing: run `build sync`")
        return 2
    license_output = args.output.with_name(LICENSE_PATH.name)
    license_output.write_text(license_file.read_text(encoding="utf-8"), encoding="utf-8")
    console.print(f"{OK} Vulhub license copied to {license_output}")
    console.print(f"  image-only        {sum(e.image_only for e in index.entries)}")
    console.print(f"  need local files  {sum(not e.image_only for e in index.entries)}")
    console.print(f"  multi-service     {sum(len(e.services) >= 2 for e in index.entries)}")
    console.print(f"  dangerous         {sum(e.is_dangerous for e in index.entries)}")
    without = sum(e.platforms is None for e in index.entries)
    mark = WARN if without else OK
    console.print(f"{mark} {without} environments with an unknown platform")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sosya.catalog.build", description=__doc__)
    parser.add_argument("--checkout", type=Path, default=DEFAULT_CHECKOUT)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("sync", help="sparse clone of Vulhub at the pinned commit")
    platforms = commands.add_parser("platforms", help="detect image platforms (resumable)")
    platforms.add_argument("--delay", type=float, default=1.0, help="seconds between lookups")
    platforms.add_argument("--refresh", action="store_true", help="also retry failed images")
    platforms.add_argument("--refresh-all", action="store_true", help="look up every image")
    index = commands.add_parser("index", help="write the packaged index.json")
    index.add_argument("--output", type=Path, default=INDEX_PATH)
    index.add_argument("--allow-missing-platforms", action="store_true")
    args = parser.parse_args(argv)
    handlers = {"sync": cmd_sync, "platforms": cmd_platforms, "index": cmd_index}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

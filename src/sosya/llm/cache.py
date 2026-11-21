"""A small cache of automatic model choices, so `sosya new` does not list models every time."""

import json
import os
import time
from pathlib import Path

TTL = 24 * 3600


def cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sosya" / "models.json"


def get(key: str, *, path: Path | None = None, now: float | None = None) -> str | None:
    path = path or cache_file()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        item = data[key]
        if (now if now is not None else time.time()) - float(item["at"]) > TTL:
            return None
        return str(item["model"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def put(key: str, model: str, *, path: Path | None = None, now: float | None = None) -> None:
    path = path or cache_file()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data[key] = {"model": model, "at": now if now is not None else time.time()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass  # a cache that cannot be written only costs one more listing next time

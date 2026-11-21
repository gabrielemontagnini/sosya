"""Local record of the ranges started from this directory, in `.sosya/state.json`.

The record is a convenience, not the source of truth: `status` and `down` also find ranges by
their Docker labels, so a range started from another directory, or one whose state was lost,
can still be listed and stopped.
"""

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

STATE_FILE = "state.json"


@dataclass(frozen=True)
class RangeState:
    name: str
    project: str
    compose_file: str
    source: str
    started_at: str
    flags: dict[str, dict[str, str]] = field(default_factory=dict)
    """Host → {"path": ..., "value": ...} of the flag injected at the last `up`."""


def load(root: Path) -> dict[str, RangeState]:
    path = root / STATE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}  # a damaged file must not block `down`; labels still find the ranges
    known = set(RangeState.__dataclass_fields__)
    return {
        name: RangeState(**{k: v for k, v in item.items() if k in known})
        for name, item in data.get("ranges", {}).items()
    }


def save(root: Path, states: dict[str, RangeState]) -> None:
    """Write atomically, so an interrupted write never leaves half a file."""
    root.mkdir(parents=True, exist_ok=True)
    data = {"ranges": {name: asdict(state) for name, state in sorted(states.items())}}
    fd, tmp = tempfile.mkstemp(dir=root, prefix=".state-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    Path(tmp).replace(root / STATE_FILE)


def record(root: Path, state: RangeState) -> None:
    states = load(root)
    states[state.name] = state
    save(root, states)


def forget(root: Path, name: str) -> None:
    states = load(root)
    if states.pop(name, None) is not None:
        save(root, states)

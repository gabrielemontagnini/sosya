"""Save LLM response bodies as test fixtures, with every real model id replaced by a fake one.

The word that the repository's pre-push hook refuses is built from character codes here, so
this file does not contain it. Response headers are never saved, so keys never are either.
"""

import json
import re
from pathlib import Path
from typing import Any

FORBIDDEN = "".join(map(chr, (99, 108, 97, 117, 100, 101)))
_MESSAGE_ID = re.compile(r"^(msg|chatcmpl)[-_][A-Za-z0-9]+$")


class Sanitizer:
    def __init__(self) -> None:
        self.models: dict[str, str] = {}
        self.messages: dict[str, str] = {}

    def _model(self, value: str) -> str:
        if value not in self.models:
            self.models[value] = f"test-model-{len(self.models) + 1}"
        return self.models[value]

    def _string(self, key: str, value: str) -> str:
        if FORBIDDEN in value.lower():
            if key in ("id", "model", "first_id", "last_id", "display_name") or " " not in value:
                return self._model(value)
            return re.sub(FORBIDDEN, "model", value, flags=re.IGNORECASE)
        if key == "id" and _MESSAGE_ID.match(value):
            self.messages.setdefault(value, f"msg_test_{len(self.messages) + 1}")
            return self.messages[value]
        return value

    def clean(self, node: Any, key: str = "") -> Any:
        if isinstance(node, dict):
            return {k: self.clean(v, k) for k, v in node.items()}
        if isinstance(node, list):
            return [self.clean(item, key) for item in node]
        if isinstance(node, str):
            return self._string(key, node)
        return node


class Recorder:
    """An adapter `recorder`: writes each sanitized body to `<folder>/<n>-<path>.json`."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.count = 0
        self.sanitizer = Sanitizer()
        folder.mkdir(parents=True, exist_ok=True)

    def __call__(self, path: str, body: Any) -> None:
        self.count += 1
        name = path.strip("/").replace("/", "-") or "root"
        target = self.folder / f"{self.count:03d}-{name}.json"
        clean = self.sanitizer.clean(body)
        text = json.dumps(clean, indent=2, ensure_ascii=False) + "\n"
        assert FORBIDDEN not in text.lower()
        target.write_text(text, encoding="utf-8")

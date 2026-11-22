"""Small helpers for terminal text."""


def plural(count: int, word: str, many: str | None = None) -> str:
    """`1 host`, `2 hosts`; `many` for irregular plurals."""
    return f"{count} {word if count == 1 else (many or word + 's')}"

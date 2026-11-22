"""Advisory ids (CVE, GHSA, CNVD, CNNVD, Struts S2-NNN) are spoilers outside the hints.

A range's name, description and objectives never contain one, unless the user's own sentence
already names it. SCENARIO.md keeps them in the last hint of each host.
"""

import re

ADVISORY = re.compile(
    r"\b("
    r"CVE-\d{4}-\d{4,}"
    r"|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
    r"|CNVD-\d{4}-\d+"
    r"|CNNVD-\d{6}-\d+"
    r"|S2-\d{3}"
    r")\b",
    re.IGNORECASE,
)
NAME_LIMIT = 40
FALLBACK_NAME = "range"


def find(text: str) -> set[str]:
    """Every advisory id in `text`, in upper case."""
    return {match.upper() for match in ADVISORY.findall(text or "")}


def spoilers(text: str, allowed: set[str]) -> list[str]:
    """The advisory ids of `text` that are not in `allowed`, sorted."""
    return sorted(find(text) - {a.upper() for a in allowed})


def strip_name(name: str, allowed: set[str] = frozenset(), fallback: str = "") -> str:
    """`name` without the advisory ids that are not allowed: `jenkins-cve-2017-1000353` becomes
    `jenkins`. An empty result becomes `fallback`, else `range`."""
    allowed_upper = {a.upper() for a in allowed}

    def drop(match: re.Match[str]) -> str:
        return match.group(0) if match.group(0).upper() in allowed_upper else ""

    cleaned = ADVISORY.sub(drop, name)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    cleaned = cleaned[:NAME_LIMIT].rstrip("-")
    if cleaned == name:
        return name
    return cleaned or fallback or FALLBACK_NAME

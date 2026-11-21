"""Pick the catalog entries the LLM may compose a range from.

The lexical search (`sosya.catalog.search`) ranks entries for the user's sentence and the
queries the LLM derived from it. Entries that cannot run on the engine are dropped, entries that
run only under emulation are marked, and dangerous entries are dropped unless the user's own
sentence names them by path or CVE id (not a query the LLM made up).
"""

from collections.abc import Sequence
from dataclasses import dataclass

from sosya.catalog.models import CatalogIndex, Entry
from sosya.catalog.search import DEFAULT_LIMIT, names_entry, search, tokenize
from sosya.spec import platform_issue


@dataclass(frozen=True)
class Candidate:
    entry: Entry
    emulated: bool = False


def candidates(
    index: CatalogIndex,
    sentence: str,
    queries: Sequence[str],
    *,
    host_platform: str | None,
    limit: int = DEFAULT_LIMIT,
) -> list[Candidate]:
    sentence_terms = tokenize(sentence)
    found: list[Candidate] = []
    for hit in search(index, [sentence, *queries], limit=None, include_dangerous=True):
        entry = hit.entry
        if entry.is_dangerous and not names_entry(sentence_terms, entry):
            continue
        if entry.platforms is None:
            continue  # an image cannot be pulled
        emulated = False
        if host_platform is not None:
            issue = platform_issue(entry, "", host_platform)
            if issue is not None and issue.level == "error":
                continue
            emulated = issue is not None
        found.append(Candidate(entry, emulated))
        if len(found) >= limit:
            break
    return found

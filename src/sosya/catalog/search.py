"""Lexical search over the catalog index, shared by `sosya catalog` and the planner.

`search` takes one query or several. The planner expands the user's sentence into keywords
(for example "CI/CD" into "jenkins" and "gitlab") and passes them all; each query is ranked
on its own and the rankings are merged with Reciprocal Rank Fusion, so every keyword gets a
fair share of the top results and entries matched by several keywords rise.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sosya.catalog.models import CatalogIndex, Entry

DEFAULT_LIMIT = 25
RRF_K = 60

STOPWORDS = frozenset(
    {
        # English filler words
        *("a", "an", "and", "are", "as", "at", "by", "for", "from", "in", "into", "is"),
        *("it", "of", "on", "or", "the", "to", "with"),
        # Words that every catalog entry shares
        *("lab", "range", "environment", "vulnerable", "vulnerability", "vulnerabilities"),
        "vulhub",
    }
)

# Field weights: an exact identifier beats a product name, which beats a word in the title.
W_IDENTIFIER = 100.0
W_PRODUCT = 20.0
W_TITLE = 6.0
W_TAG = 4.0
W_COMPONENT = 3.0  # service and image names
W_SUMMARY = 1.0
PREFIX_FACTOR = 0.5
MIN_PREFIX = 3

_CVE = re.compile(r"cve-\d{4}-\d{4,}")
_PATH = re.compile(r"(?:vulhub/)?[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*")
_WORD = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


@dataclass(frozen=True)
class Hit:
    entry: Entry
    score: float
    matched: tuple[str, ...]
    """The queries that matched this entry, in the order they were given."""


def tokenize(text: str) -> list[str]:
    """Lowercase tokens. CVE ids, `product/env` paths and hyphenated words stay whole,
    and hyphenated words also yield their parts (`s2-045` gives `s2-045`, `s2`, `045`)."""
    text = text.lower()
    tokens: list[str] = []
    for match in _PATH.finditer(text):
        tokens.append(match.group().removeprefix("vulhub/"))
    for match in _CVE.finditer(text):
        tokens.append(match.group())
    text = _CVE.sub(" ", text)
    for word in _WORD.findall(text):
        tokens.append(word)
        if "-" in word:
            tokens.extend(word.split("-"))
    return [t for t in dict.fromkeys(tokens) if t not in STOPWORDS]


@dataclass(frozen=True)
class _Doc:
    entry: Entry
    identifiers: frozenset[str]
    product: frozenset[str]
    title: frozenset[str]
    tags: frozenset[str]
    components: frozenset[str]
    summary: frozenset[str]


def _doc(entry: Entry) -> _Doc:
    identifiers = {entry.path.lower(), *(cve.lower() for cve in entry.cves)}
    components: set[str] = set()
    for service in entry.services:
        components.update(tokenize(service.name))
        for image in (service.image, *service.base_images):
            if image:
                components.update(tokenize(image.replace("/", " ").replace(":", " ")))
    return _Doc(
        entry=entry,
        identifiers=frozenset(identifiers),
        product=frozenset(tokenize(f"{entry.product} {entry.product_dir}")),
        title=frozenset(tokenize(entry.title)),
        tags=frozenset(tokenize(" ".join(entry.tags))),
        components=frozenset(components),
        summary=frozenset(tokenize(entry.summary)),
    )


def _field_score(term: str, tokens: frozenset[str], weight: float) -> float:
    if term in tokens:
        return weight
    if len(term) >= MIN_PREFIX and any(token.startswith(term) for token in tokens):
        return weight * PREFIX_FACTOR
    return 0.0


def _term_score(term: str, doc: _Doc) -> float:
    if term in doc.identifiers:
        return W_IDENTIFIER
    return max(
        _field_score(term, doc.product, W_PRODUCT),
        _field_score(term, doc.title, W_TITLE),
        _field_score(term, doc.tags, W_TAG),
        _field_score(term, doc.components, W_COMPONENT),
        _field_score(term, doc.summary, W_SUMMARY),
    )


def score(terms: Sequence[str], doc: _Doc) -> float:
    """Sum of the best field score of each term, scaled by the share of terms that match."""
    scores = [_term_score(term, doc) for term in terms]
    matched = sum(1 for s in scores if s > 0)
    if not matched:
        return 0.0
    return sum(scores) * matched / len(terms)


def names_entry(terms: Iterable[str], entry: Entry) -> bool:
    """True if a query names `entry` explicitly: its path or one of its CVE ids."""
    wanted = {entry.path.lower(), *(cve.lower() for cve in entry.cves)}
    return any(term in wanted for term in terms)


_NOT_NAMED = 1_000_000


def _named_rank(term_lists: Sequence[tuple[str, list[str]]], entry: Entry) -> int:
    """1 + the position of the first query that names `entry`, or 0 if none does."""
    for position, (_, terms) in enumerate(term_lists, start=1):
        if names_entry(terms, entry):
            return position
    return 0


def _rank(terms: Sequence[str], docs: Sequence[_Doc]) -> list[tuple[_Doc, float]]:
    scored = [(doc, score(terms, doc)) for doc in docs]
    hits = [(doc, s) for doc, s in scored if s > 0]
    return sorted(hits, key=lambda item: (-item[1], item[0].entry.id))


def search(
    index: CatalogIndex,
    queries: str | Sequence[str] | None,
    *,
    limit: int | None = DEFAULT_LIMIT,
    include_dangerous: bool = False,
) -> list[Hit]:
    """Rank catalog entries for one query or several, best first.

    With no usable query terms, every entry is returned in id order. Dangerous entries are
    left out unless `include_dangerous` is true or a query names them by path or CVE id.
    """
    query_list = [queries] if isinstance(queries, str) else list(queries or [])
    query_list = list(dict.fromkeys(q.strip() for q in query_list if q.strip()))
    term_lists = [(query, tokenize(query)) for query in query_list]
    term_lists = [(query, terms) for query, terms in term_lists if terms]
    all_terms = [term for _, terms in term_lists for term in terms]
    docs = [
        _doc(entry)
        for entry in index.entries
        if include_dangerous or not entry.is_dangerous or names_entry(all_terms, entry)
    ]
    if not term_lists:
        hits = [Hit(doc.entry, 0.0, ()) for doc in sorted(docs, key=lambda d: d.entry.id)]
        return hits[:limit] if limit is not None else hits

    fused: dict[str, float] = {}
    matched: dict[str, list[str]] = {}
    entries: dict[str, Entry] = {}
    for query, terms in term_lists:
        for rank, (doc, _) in enumerate(_rank(terms, docs), start=1):
            entry_id = doc.entry.id
            fused[entry_id] = fused.get(entry_id, 0.0) + 1.0 / (RRF_K + rank)
            matched.setdefault(entry_id, []).append(query)
            entries[entry_id] = doc.entry
    # An entry a query names by path or CVE id comes first, whatever the fusion says: a
    # generic word matched by several queries must not push it down.
    named = {e: n for e, n in ((i, _named_rank(term_lists, entries[i])) for i in fused) if n}
    ordered = sorted(
        fused,
        key=lambda entry_id: (named.get(entry_id, _NOT_NAMED), -fused[entry_id], entry_id),
    )
    hits = [Hit(entries[i], round(fused[i], 6), tuple(matched[i])) for i in ordered]
    return hits[:limit] if limit is not None else hits

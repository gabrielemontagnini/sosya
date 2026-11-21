from sosya.catalog.models import CatalogIndex, DangerReason, Entry, Service
from sosya.catalog.search import search, tokenize


def _entry(path: str, product: str, title: str, **extra) -> Entry:
    return Entry(
        id=f"vulhub/{path}",
        path=path,
        product=product,
        product_dir=path.split("/")[0],
        title=title,
        services=extra.pop(
            "services", [Service(name="web", image=f"vulhub/{path.split('/')[0]}:1")]
        ),
        **extra,
    )


ENTRIES = [
    _entry(
        "jenkins/CVE-2018-1000861",
        "Jenkins",
        "Jenkins Remote Command Execution",
        cves=["CVE-2018-1000861"],
        tags=["RCE"],
    ),
    _entry(
        "jenkins/CVE-2017-1000353",
        "Jenkins",
        "Jenkins Java Deserialization RCE",
        cves=["CVE-2017-1000353"],
        tags=["Deserialization", "RCE"],
    ),
    _entry(
        "gitlab/CVE-2021-22205",
        "GitLab",
        "GitLab Pre-Auth Remote Command Execution",
        cves=["CVE-2021-22205"],
        tags=["RCE"],
    ),
    _entry(
        "redis/4-unacc",
        "Redis",
        "Redis Post Exploitation via Master-Slave Sync",
        tags=["RCE", "Database"],
        summary="Redis is an in-memory database.",
    ),
    _entry(
        "struts2/s2-045",
        "Apache Struts2",
        "S2-045 Remote Code Execution",
        cves=["CVE-2017-5638"],
        summary="Struts is a Java web framework.",
    ),
    _entry(
        "log4j/CVE-2021-44228",
        "Apache Log4j",
        "Log4j2 JNDI Injection",
        cves=["CVE-2021-44228"],
        summary="Log4j is used by many Java servers such as Redis-less apps.",
    ),
    _entry(
        "docker/unauthorized-rce",
        "Docker",
        "Docker Remote API Unauthorized Access",
        dangerous=[DangerReason(service="docker", reason="privileged")],
    ),
    _entry(
        "thinkphp/5-rce",
        "ThinkPHP",
        "ThinkPHP5 Remote Code Execution",
        summary="A Chinese PHP framework, often deployed with Jenkins pipelines.",
    ),
]
INDEX = CatalogIndex(vulhub_commit="abc", entries=ENTRIES)


def ids(hits) -> list[str]:
    return [hit.entry.path for hit in hits]


def test_tokenize_keeps_identifiers_whole() -> None:
    assert tokenize("CVE-2021-44228 in vulhub/struts2/s2-045") == [
        "struts2/s2-045",
        "cve-2021-44228",
        "struts2",
        "s2-045",
        "s2",
        "045",
    ]
    assert tokenize("The Redis lab") == ["redis"]


def test_exact_cve_comes_first() -> None:
    assert ids(search(INDEX, "cve-2017-5638"))[0] == "struts2/s2-045"
    assert ids(search(INDEX, "CVE-2021-44228")) == ["log4j/CVE-2021-44228"]


def test_exact_path_comes_first() -> None:
    assert ids(search(INDEX, "redis/4-unacc"))[0] == "redis/4-unacc"


def test_product_beats_title_beats_summary() -> None:
    # "jenkins" is the product of two entries and only a summary word of thinkphp.
    assert ids(search(INDEX, "jenkins")) == [
        "jenkins/CVE-2017-1000353",
        "jenkins/CVE-2018-1000861",
        "thinkphp/5-rce",
    ]
    # "redis" is redis's product but only a summary word of log4j.
    assert ids(search(INDEX, "redis")) == ["redis/4-unacc", "log4j/CVE-2021-44228"]


def test_prefix_matches_at_lower_weight() -> None:
    hits = search(INDEX, "strut")
    assert ids(hits) == ["struts2/s2-045"]


def test_more_matching_words_rank_higher() -> None:
    assert ids(search(INDEX, "jenkins deserialization"))[0] == "jenkins/CVE-2017-1000353"


def test_ties_are_broken_by_id() -> None:
    # Four entries share the title word "remote" with the same weight.
    assert ids(search(INDEX, "remote")) == [
        "gitlab/CVE-2021-22205",
        "jenkins/CVE-2018-1000861",
        "struts2/s2-045",
        "thinkphp/5-rce",
    ]


def test_multiple_queries_are_fused() -> None:
    hits = search(INDEX, ["jenkins", "gitlab"])
    top = ids(hits)[:3]
    assert "gitlab/CVE-2021-22205" in top
    assert top[0].startswith(("jenkins/", "gitlab/"))
    assert {h.entry.path: h.matched for h in hits}["gitlab/CVE-2021-22205"] == ("gitlab",)


def test_entries_matched_by_several_queries_rise() -> None:
    hits = search(INDEX, ["java", "rce"])
    assert {h.entry.path: h.matched for h in hits}["jenkins/CVE-2017-1000353"] == ("java", "rce")
    assert ids(hits)[0] == "jenkins/CVE-2017-1000353"


def test_duplicate_and_blank_queries_are_ignored() -> None:
    assert search(INDEX, ["redis", "redis", " "]) == search(INDEX, "redis")


def test_limit_defaults_to_25() -> None:
    many = CatalogIndex(
        vulhub_commit="abc",
        entries=[_entry(f"app{i:02}/x", "App", f"App {i} RCE") for i in range(40)],
    )
    assert len(search(many, "app")) == 25
    assert len(search(many, "app", limit=None)) == 40


def test_empty_query_lists_everything_by_id() -> None:
    hits = search(INDEX, "", limit=None, include_dangerous=True)
    assert ids(hits) == sorted(e.path for e in ENTRIES)
    assert search(INDEX, ["the", "lab"], limit=None, include_dangerous=True) == hits


def test_entries_named_by_path_or_cve_come_first() -> None:
    hits = search(INDEX, ["redis/4-unacc", "CVE-2017-5638", "rce"])
    assert ids(hits)[:2] == ["redis/4-unacc", "struts2/s2-045"]


def test_path_with_a_cve_stays_whole() -> None:
    assert "log4j/cve-2021-44228" in tokenize("log4j/CVE-2021-44228")
    assert ids(search(INDEX, "vulhub/log4j/CVE-2021-44228")) == ["log4j/CVE-2021-44228"]


def test_dangerous_entries_are_left_out_unless_named() -> None:
    assert "docker/unauthorized-rce" not in ids(search(INDEX, "docker remote api"))
    assert "docker/unauthorized-rce" not in ids(search(INDEX, "", limit=None))
    assert ids(search(INDEX, "docker/unauthorized-rce"))[0] == "docker/unauthorized-rce"
    named = ids(search(INDEX, ["redis", "vulhub/docker/unauthorized-rce"]))
    assert "docker/unauthorized-rce" in named
    assert "docker/unauthorized-rce" in ids(search(INDEX, "docker", include_dangerous=True))


def test_no_match_returns_nothing() -> None:
    assert search(INDEX, "sharepoint") == []

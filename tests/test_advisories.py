import pytest

from sosya import advisories


def test_find_every_kind_of_id() -> None:
    text = (
        "cve-2021-44228, CVE-2017-1000353, GHSA-jfh8-c2jp-5v3q, CNVD-2018-24942, "
        "CNNVD-201909-1234 and s2-045"
    )
    assert advisories.find(text) == {
        "CVE-2021-44228",
        "CVE-2017-1000353",
        "GHSA-JFH8-C2JP-5V3Q",
        "CNVD-2018-24942",
        "CNNVD-201909-1234",
        "S2-045",
    }


@pytest.mark.parametrize(
    "text", ["struts2 on port 8080", "redis 4.0.14", "a pwn lab", "ts2-045", "CVE-2021"]
)
def test_find_ignores_other_words(text: str) -> None:
    assert advisories.find(text) == set()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("jenkins-cve-2017-1000353", "jenkins"),
        ("cve-2021-44228-solr", "solr"),
        ("struts2-s2-045-dmz", "struts2-dmz"),
        ("dmz-redis", "dmz-redis"),
        ("cve-2021-44228", "range"),
    ],
)
def test_strip_name(name: str, expected: str) -> None:
    assert advisories.strip_name(name) == expected


def test_strip_name_keeps_allowed_ids_and_uses_the_fallback() -> None:
    assert advisories.strip_name("log4j-cve-2021-44228", {"CVE-2021-44228"}) == (
        "log4j-cve-2021-44228"
    )
    assert advisories.strip_name("cve-2021-44228", fallback="solr") == "solr"


def test_spoilers() -> None:
    assert advisories.spoilers("CVE-2021-44228 and CVE-2017-5638", {"cve-2021-44228"}) == [
        "CVE-2017-5638"
    ]

from sosya.text import plural


def test_plural() -> None:
    assert plural(1, "host") == "1 host"
    assert plural(2, "host") == "2 hosts"
    assert plural(0, "problem") == "0 problems"
    assert plural(3, "entry", "entries") == "3 entries"

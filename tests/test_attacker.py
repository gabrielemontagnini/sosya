from pathlib import Path

import pytest

from sosya import __version__, attacker


def test_default_image_is_the_published_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(attacker.IMAGE_ENV, raising=False)
    assert attacker.image() == f"ghcr.io/gabrielemontagnini/sosya-attacker:{__version__}"
    monkeypatch.setenv(attacker.IMAGE_ENV, "sosya-attacker:dev")
    assert attacker.image() == "sosya-attacker:dev"


def test_dockerfile_ships_in_the_package() -> None:
    with attacker.build_context() as context:
        dockerfile = (context / "Dockerfile").read_text()
    assert "FROM kalilinux/kali-rolling@sha256:" in dockerfile
    for tool in ("nmap", "curl", "redis-tools", "netcat-openbsd"):
        assert tool in dockerfile
    assert "metasploit" not in dockerfile


def test_build_command() -> None:
    assert attacker.build_command("img:1", Path("/ctx")) == [
        "docker",
        "build",
        "--tag",
        "img:1",
        "/ctx",
    ]

"""Every range in the packaged gallery is valid and passes the catalog checks on amd64."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from sosya import gallery, runtime
from sosya.catalog.loader import load_index
from sosya.cli import app
from sosya.spec import check_catalog, errors, load_range


def test_the_gallery_has_dmz_redis() -> None:
    assert "dmz-redis" in gallery.names()
    path = gallery.path("dmz-redis")
    assert path is not None and (path / "range.yaml").is_file()


GALLERY = {"dmz-redis", "wordpress", "solr", "grafana", "drupal", "file-server", "jenkins"}


def test_the_gallery_has_seven_ranges() -> None:
    assert set(gallery.names()) == GALLERY


@pytest.mark.parametrize("name", gallery.names())
def test_gallery_ranges_give_nothing_away(name: str) -> None:
    from sosya import advisories

    path = gallery.path(name)
    assert path is not None
    spec = load_range(path)
    for text in (spec.name, spec.description, *spec.objectives):
        assert advisories.find(text) == set(), text


def test_unknown_gallery_name() -> None:
    assert gallery.path("no-such-range") is None


@pytest.mark.parametrize("name", gallery.names())
def test_gallery_range_is_valid(name: str) -> None:
    path = gallery.path(name)
    assert path is not None
    spec = load_range(path)
    assert spec.name == name
    issues = check_catalog(spec, load_index(), host_platform="linux/amd64")
    assert errors(issues) == []


def test_up_finds_a_gallery_range_from_an_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    seen: dict[str, Path] = {}

    def fake_up(path: Path, *, report, confirm, allow_privileged: bool, exposure) -> None:
        seen["path"] = path

    monkeypatch.setattr(runtime, "up", fake_up)
    result = CliRunner().invoke(app, ["up", "dmz-redis"])
    assert result.exit_code == 0, result.output
    assert seen["path"] == gallery.path("dmz-redis")


def test_ranges_folder_wins_over_the_gallery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    local = tmp_path / "ranges" / "dmz-redis"
    local.mkdir(parents=True)
    (local / "range.yaml").write_text((gallery.path("dmz-redis") / "range.yaml").read_text())
    seen: dict[str, Path] = {}

    def fake_up(path: Path, *, report, confirm, allow_privileged: bool, exposure) -> None:
        seen["path"] = path

    monkeypatch.setattr(runtime, "up", fake_up)
    result = CliRunner().invoke(app, ["up", "dmz-redis"])
    assert result.exit_code == 0, result.output
    assert seen["path"] == Path("ranges") / "dmz-redis"


def test_unknown_range_lists_the_gallery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["up", "nope"])
    assert result.exit_code == 1
    assert "dmz-redis" in result.output

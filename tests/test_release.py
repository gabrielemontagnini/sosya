"""The release notes script that release.yml uses for the GitHub release."""

import re
import subprocess
from pathlib import Path

import pytest

from sosya import __version__

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "release-notes.sh"

# The sdist ships the tests but not .github/.
pytestmark = pytest.mark.skipif(not SCRIPT.exists(), reason="needs the repository checkout")

CHANGELOG = """# Changelog

## [Unreleased]

## [0.2.0] - 2026-12-01

### Added

- Something new.

## [0.1.0] - 2026-11-24

The first release.

### Added

- Everything.

[Unreleased]: https://example.org/compare/v0.2.0...HEAD
[0.2.0]: https://example.org/v0.2.0
[0.1.0]: https://example.org/v0.1.0
"""


def notes(version: str, changelog: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), version, str(changelog)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def changelog(tmp_path: Path) -> Path:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(CHANGELOG)
    return path


def test_a_section_stops_at_the_next_one(changelog: Path) -> None:
    result = notes("0.2.0", changelog)
    assert result.returncode == 0
    assert result.stdout == "### Added\n\n- Something new.\n"


def test_the_last_section_leaves_out_the_links(changelog: Path) -> None:
    result = notes("0.1.0", changelog)
    assert result.returncode == 0
    assert result.stdout == "The first release.\n\n### Added\n\n- Everything.\n"


@pytest.mark.parametrize("version", ["0.1.0rc1", "0.1.0a2", "0.1.0b3"])
def test_a_pre_release_uses_the_section_of_its_final_version(changelog: Path, version: str) -> None:
    assert notes(version, changelog).stdout == notes("0.1.0", changelog).stdout


@pytest.mark.parametrize("version", ["0.3.0", "Unreleased"])
def test_a_missing_or_empty_section_fails(changelog: Path, version: str) -> None:
    result = notes(version, changelog)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "no section" in result.stderr


def test_the_changelog_has_notes_for_the_current_version() -> None:
    base = re.sub(r"(a|b|rc)[0-9]+$", "", __version__)
    result = notes(__version__, ROOT / "CHANGELOG.md")
    assert result.returncode == 0, f"CHANGELOG.md has no section for {base}"
    assert result.stdout.strip()

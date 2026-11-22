#!/usr/bin/env bash
# Prints the CHANGELOG.md section of a version, the body of the GitHub release.
# A pre-release (0.1.0rc1, 0.1.0a1, 0.1.0b1) uses the section of its final version (0.1.0).
# Usage: release-notes.sh <version> [changelog]. Fails if the section is missing or empty.
set -euo pipefail

version="${1:?usage: release-notes.sh <version> [changelog]}"
changelog="${2:-CHANGELOG.md}"
base=$(printf '%s\n' "$version" | sed -E 's/(a|b|rc)[0-9]+$//')

notes=$(awk -v heading="## [$base]" '
  index($0, heading) == 1 { found = 1; next }
  found && (/^## \[/ || /^\[[^]]+\]: /) { exit }
  found { print }
' "$changelog" | sed -e '/./,$!d')

if [ -z "${notes//[[:space:]]/}" ]; then
  echo "no section for $base in $changelog" >&2
  exit 1
fi
printf '%s\n' "$notes"

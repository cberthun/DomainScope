#!/usr/bin/env bash
# Builds dist/domainscope-<version>.tar.gz and its .sha256 from the files of the repository
# (tracked files plus new, not ignored files; tests, CI and development files are left out).
#
#   scripts/make-release.sh [--output DIR]
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUT="${2:?}"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

cd "$ROOT"
VERSION="$(tr -d '[:space:]' <VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid VERSION: $VERSION" >&2; exit 1; }
grep -q "^## \[$VERSION\]" CHANGELOG.md || { echo "CHANGELOG.md has no section for $VERSION" >&2; exit 1; }

NAME="domainscope-$VERSION"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME" "$OUT"

# Files that are not part of a release
EXCLUDE='^(tests/|\.github/|\.phpunit\.cache/|\.claude/|phpunit\.xml$|composer\.lock$|\.editorconfig$|\.gitattributes$|scripts/make-release\.sh$|dist/)'

git ls-files -z --cached --others --exclude-standard \
  | grep -zEv "$EXCLUDE" \
  | while IFS= read -r -d '' f; do [[ -f "$f" ]] && printf '%s\0' "$f"; done \
  | rsync -a --from0 --files-from=- ./ "$STAGE/$NAME/"

# runtime directories that are not versioned
mkdir -p "$STAGE/$NAME"/storage/{cache,logs,reports}
touch "$STAGE/$NAME"/storage/{cache,logs,reports}/.gitkeep

# reproducible archive
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2026-01-01 00:00:00' \
  -czf "$OUT/$NAME.tar.gz" -C "$STAGE" "$NAME"
( cd "$OUT" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256" )
echo "Created $OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"

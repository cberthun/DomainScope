#!/usr/bin/env bash
# DomainScope - controlled update with backup, integrity check, health check and automatic rollback.
#
#   sudo ./update.sh                          update to the latest GitHub release
#   sudo ./update.sh --version 1.1.0          update to a specific version
#   sudo ./update.sh --file rel.tar.gz --sha256 <hash>    offline update from a local archive
#   sudo ./update.sh --check                  only show the installed and the available version
#
# The release source is the GitHub repository cberthun/DomainScope (override: DS_REPO=owner/name). Every release
# carries domainscope-<version>.tar.gz and domainscope-<version>.tar.gz.sha256.
# Your .env, the database content and storage/cache|logs|reports|sessions are not touched by an update.
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
INSTALL_DIR="${DS_INSTALL_DIR:-$(dirname -- "$SELF")}"
# shellcheck source=scripts/lib.sh
source "$INSTALL_DIR/scripts/lib.sh"

TARGET=""; FILE=""; SHA=""; CHECK=0; FORCE=0; ALLOW_DOWNGRADE=0; ASSUME_YES=0; NON_INTERACTIVE=0; KEEP=10
usage() {
  cat <<'EOF'
Usage: update.sh [options]
  --version X.Y.Z       target version (default: newest release in the GitHub repository)
  --file ARCHIVE        local release archive instead of a download (requires --sha256)
  --sha256 HASH         expected SHA-256 of the archive (mandatory with --file)
  --check               only show versions
  --force               reinstall even if the version is the same
  --allow-downgrade     allow a downgrade to an older version
  --keep N              number of backups to keep (default 10)
  -y, --yes             answer questions with "yes"
  --non-interactive     no questions
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) TARGET="${2:?}"; shift ;;
    --file) FILE="${2:?}"; shift ;;
    --sha256) SHA="${2:?}"; shift ;;
    --check) CHECK=1 ;;
    --force) FORCE=1 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    --keep) KEEP="${2:?}"; shift ;;
    -y|--yes) ASSUME_YES=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

WORK=""; BACKUP=""; MIGRATED=0; SWITCHED=0
cleanup() { [[ -n "$WORK" && -d "$WORK" ]] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

# Restore code (and, if migrations ran, the database) from the backup made at the start.
rollback() {
  warn "Rolling back to the previous version"
  local rb; rb="$(mktemp -d)"
  if tar -xzf "$BACKUP/app.tar.gz" -C "$rb" && sync_tree "$rb" "$INSTALL_DIR"; then
    apply_permissions
    if [[ "$MIGRATED" -eq 1 ]]; then
      db_restore "$BACKUP/db.sql.gz" && ok "Database restored" || err "Restoring the database failed - restore it manually from $BACKUP/db.sql.gz (restore.sh)."
    fi
    ok "Previous version restored. Backup: $BACKUP"
  else
    err "Automatic rollback failed. Restore manually with: $INSTALL_DIR/restore.sh $BACKUP"
  fi
  rm -rf "$rb"
}

fail_update() {
  err "$*"
  [[ "$SWITCHED" -eq 1 ]] && rollback
  exit 1
}

main() {
  [[ -f "$INSTALL_DIR/.env" ]] || die "No installation found in $INSTALL_DIR."
  require_root_or_owner
  local current; current="$(installed_version)"
  valid_version "$current" || die "The installed version could not be determined ($INSTALL_DIR/VERSION)."

  local target="$TARGET" archive="" expected=""
  if [[ -z "$FILE" ]]; then
    if [[ -z "$target" ]]; then
      target="$(latest_release_version)" || die "Could not query the latest release of $DS_REPO."
    fi
    valid_version "$target" || die "Invalid version: $target"
  fi

  if [[ "$CHECK" -eq 1 ]]; then
    echo "Installed: $current"
    echo "Available: ${target:-<from archive>}"
    if [[ -n "$target" ]] && version_gt "$target" "$current"; then echo "An update is available (sudo $INSTALL_DIR/update.sh)."; else echo "DomainScope is up to date."; fi
    return 0
  fi

  # --- single run only -----------------------------------------------------------------------------
  mkdir -p "$INSTALL_DIR/storage"
  exec 9>"$INSTALL_DIR/storage/update.lock"
  flock -n 9 || die "Another update is running."

  WORK="$(mktemp -d)"
  if [[ -n "$FILE" ]]; then
    [[ -f "$FILE" ]] || die "File not found: $FILE"
    [[ -n "$SHA" ]] || die "--file requires --sha256."
    archive="$FILE"; expected="$SHA"
  else
    info "Downloading DomainScope $target"
    archive="$WORK/domainscope-$target.tar.gz"
    download "$(release_asset_url "$target" "domainscope-$target.tar.gz")" "$archive" || die "Download of the release archive failed."
    download "$(release_asset_url "$target" "domainscope-$target.tar.gz.sha256")" "$WORK/sum" || die "Download of the checksum file failed."
    expected="$(awk '{print $1; exit}' "$WORK/sum")"
    [[ -z "$SHA" || "${SHA,,}" == "${expected,,}" ]] || die "--sha256 differs from the published checksum."
  fi
  verify_sha256 "$archive" "$expected"
  ok "Checksum verified"
  check_archive_safe "$archive"

  mkdir "$WORK/new"
  tar -xzf "$archive" -C "$WORK/new" --strip-components=1
  [[ -f "$WORK/new/VERSION" && -f "$WORK/new/app/bootstrap.php" && -f "$WORK/new/bin/migrate.php" && -f "$WORK/new/scripts/lib.sh" ]] \
    || die "The archive does not look like a DomainScope release."
  local new; new="$(tr -d '[:space:]' <"$WORK/new/VERSION")"
  valid_version "$new" || die "The archive has an invalid VERSION."
  [[ -z "$target" || "$new" == "$target" ]] || die "The archive contains version $new, expected $target."

  if [[ "$new" == "$current" && "$FORCE" -eq 0 ]]; then ok "Already at version $current (use --force to reinstall)."; return 0; fi
  if version_gt "$current" "$new" && [[ "$ALLOW_DOWNGRADE" -eq 0 ]]; then
    die "$new is older than the installed $current (use --allow-downgrade; a downgrade may not work with a newer database schema)."
  fi
  info "Update $current -> $new"
  confirm "Continue?" y || { info "Aborted."; return 0; }

  # --- backup ----------------------------------------------------------------------------------------
  info "Creating a backup"
  BACKUP="$(create_backup "before-$new")"
  ok "Backup: $BACKUP"

  # --- switch ----------------------------------------------------------------------------------------
  SWITCHED=1
  sync_tree "$WORK/new" "$INSTALL_DIR" || fail_update "Copying the new files failed."
  apply_permissions
  info "Running migrations"
  local out
  if ! out="$(cd "$INSTALL_DIR" && run_php bin/migrate.php 2>&1)"; then
    # a failed migration may be half-applied
    MIGRATED=1
    echo "$out"
    fail_update "Migration failed."
  fi
  echo "$out"
  if grep -qE '^[1-9][0-9]* Migration' <<<"$out"; then MIGRATED=1; fi

  info "Health check"
  run_php "$INSTALL_DIR/bin/health.php" || fail_update "The health check failed."
  http_check || fail_update "The web interface answers with a server error."

  SWITCHED=0
  prune_backups "$KEEP"
  ok "DomainScope $new is installed. (Backup of the old version: $BACKUP)"
}

# A 5xx from the running site after the update counts as failure; an unreachable site is only a warning.
http_check() {
  have curl || return 0
  local url code; url="$(env_get APP_URL || true)"
  [[ "$url" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || return 0
  code="$(curl -ks -o /dev/null -w '%{http_code}' --max-time 10 "$url/login" || echo 000)"
  case "$code" in
    5??) err "GET $url/login -> $code"; return 1 ;;
    000) warn "$url is not reachable from this server (skipped web check)." ;;
    *) ok "Web interface answers ($code)" ;;
  esac
  return 0
}

main "$@"
exit $?

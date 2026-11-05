#!/usr/bin/env bash
# DomainScope - restore a backup made by backup.sh or update.sh (database, code, .env).
#
#   sudo ./restore.sh /var/backups/domainscope/domainscope-<time>-<label> [--code-only|--db-only] [--yes]
#
# Replaces the current database content and files. A safety backup of the current state is made first.
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
INSTALL_DIR="${DS_INSTALL_DIR:-$(dirname -- "$SELF")}"
# shellcheck source=scripts/lib.sh
source "$INSTALL_DIR/scripts/lib.sh"

SRC=""; CODE=1; DB=1; ASSUME_YES=0; NON_INTERACTIVE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --code-only) DB=0 ;;
    --db-only) CODE=0 ;;
    -y|--yes) ASSUME_YES=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    -h|--help) sed -n '2,7p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "Unknown option: $1" ;;
    *) SRC="$1" ;;
  esac
  shift
done

[[ -n "$SRC" && -d "$SRC" ]] || die "Usage: restore.sh <backup directory>"
[[ -f "$SRC/db.sql.gz" && -f "$SRC/app.tar.gz" && -f "$SRC/env" ]] || die "$SRC is not a DomainScope backup."
[[ -f "$INSTALL_DIR/.env" ]] || die "No installation found in $INSTALL_DIR."
require_root_or_owner

info "Restoring $(basename "$SRC") (version $(cat "$SRC/VERSION" 2>/dev/null || echo '?'))"
confirm "This replaces the current database and files. Continue?" n || { info "Aborted."; exit 0; }

safety="$(create_backup before-restore)"
ok "Safety backup of the current state: $safety"

if [[ "$CODE" -eq 1 ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  tar -xzf "$SRC/app.tar.gz" -C "$tmp"
  sync_tree "$tmp" "$INSTALL_DIR"
  cp -p "$SRC/env" "$INSTALL_DIR/.env"
  apply_permissions
  ok "Code and configuration restored"
fi
if [[ "$DB" -eq 1 ]]; then
  db_restore "$SRC/db.sql.gz" || die "Restoring the database failed. The safety backup is in $safety."
  ok "Database restored"
fi
run_php "$INSTALL_DIR/bin/health.php" || warn "The health check reports problems."
ok "Restore finished."

#!/usr/bin/env bash
# DomainScope - backup of database, configuration (.env) and code/data files.
#
#   sudo ./backup.sh [--dir /var/backups/domainscope] [--keep 10]
#
# Creates <dir>/domainscope-<time>-manual/{db.sql.gz,app.tar.gz,env,VERSION}. The backup contains secrets (.env, APP_KEY, password hash) -
# keep it private (directory mode 0700).
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
INSTALL_DIR="${DS_INSTALL_DIR:-$(dirname -- "$SELF")}"
# shellcheck source=scripts/lib.sh
source "$INSTALL_DIR/scripts/lib.sh"

KEEP=10
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DS_BACKUP_DIR="${2:?}"; shift ;;
    --keep) KEEP="${2:?}"; shift ;;
    -h|--help) sed -n '2,8p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

[[ -f "$INSTALL_DIR/.env" ]] || die "No installation found in $INSTALL_DIR."
require_root_or_owner
dir="$(create_backup manual)"
prune_backups "$KEEP"
ok "Backup created: $dir"

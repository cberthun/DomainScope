#!/usr/bin/env bash
# DomainScope - uninstall. Removes the cron job, the virtual host and the installation directory.
#
#   sudo ./uninstall.sh [--drop-database] [--keep-backups]
#
# A final backup is made first and kept in /var/backups/domainscope. The database is only dropped with --drop-database.
set -Eeuo pipefail
IFS=$'\n\t'

SELF="$(readlink -f -- "${BASH_SOURCE[0]}")"
INSTALL_DIR="${DS_INSTALL_DIR:-$(dirname -- "$SELF")}"
# shellcheck source=scripts/lib.sh
source "$INSTALL_DIR/scripts/lib.sh"

DROP_DB=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --drop-database) DROP_DB=1 ;;
    --keep-backups) ;;
    -h|--help) sed -n '2,6p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

require_root
[[ -f "$INSTALL_DIR/.env" ]] || die "No installation found in $INSTALL_DIR."
echo "This removes DomainScope from $INSTALL_DIR."
confirm_phrase "uninstall domainscope" || die "Aborted."

dir="$(create_backup final)"
ok "Final backup: $dir"

rm -f "$CRON_FILE"
for f in /etc/nginx/sites-enabled/domainscope /etc/nginx/sites-available/domainscope; do rm -f "$f"; done
if have a2dissite && [[ -e /etc/apache2/sites-available/domainscope.conf ]]; then
  a2dissite -q domainscope || true
  rm -f /etc/apache2/sites-available/domainscope.conf
fi
have nginx && nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
have apache2ctl && apache2ctl configtest >/dev/null 2>&1 && systemctl reload apache2 2>/dev/null || true

if [[ "$DROP_DB" -eq 1 ]]; then
  name="$(env_get DB_NAME)"; user="$(env_get DB_USER)"
  if [[ "$(env_get DB_HOST)" =~ ^(127\.0\.0\.1|localhost)$ ]]; then
    "$(db_client)" -e "DROP DATABASE IF EXISTS \`$name\`; DROP USER IF EXISTS '$user'@'localhost';" && ok "Database and user removed"
  else
    warn "The database server is remote - the database was not dropped."
  fi
fi

cd /
rm -rf -- "${INSTALL_DIR:?}"
ok "DomainScope removed. Backup kept in $dir"

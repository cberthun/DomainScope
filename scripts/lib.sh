#!/usr/bin/env bash
# Shared helpers for install.sh, update.sh, backup.sh, restore.sh and uninstall.sh.
# Sourced, never executed. Requires bash >= 4; callers use 'set -Eeuo pipefail' (db_dump relies on pipefail).

DS_REPO="${DS_REPO:-cberthun/DomainScope}"
DS_DEFAULT_INSTALL_DIR="/var/www/domainscope"
DS_DEFAULT_BACKUP_DIR="/var/backups/domainscope"
DS_WEB_USER_DEFAULT="www-data"

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi

ts()   { date '+%Y-%m-%d %H:%M:%S'; }
info() { printf '%s[%s]%s %s\n' "$C_BLU" "$(ts)" "$C_RST" "$*"; }
ok()   { printf '%s[%s] ✔%s %s\n' "$C_GRN" "$(ts)" "$C_RST" "$*"; }
warn() { printf '%s[%s] ! %s%s\n' "$C_YEL" "$(ts)" "$*" "$C_RST" >&2; }
err()  { printf '%s[%s] ✘ %s%s\n' "$C_RED" "$(ts)" "$*" "$C_RST" >&2; }
die()  { err "$*"; exit "${DIE_CODE:-1}"; }
have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "This script needs root privileges. Please run it with 'sudo $0 ...'."
}

# Root, or the owner of the installation directory (then no chown is needed).
require_root_or_owner() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] && return 0
  [[ -O "${INSTALL_DIR:?}" ]] || die "Run this script as root (sudo) or as the owner of $INSTALL_DIR."
}

# confirm "Question?" [y|n] -> 0 for yes. --yes answers yes; non-interactive uses the default.
confirm() {
  local question="$1" default="${2:-n}" reply prompt
  [[ "${ASSUME_YES:-0}" == "1" ]] && return 0
  if [[ "${NON_INTERACTIVE:-0}" == "1" || ! -t 0 ]]; then
    [[ "$default" == "y" ]]; return
  fi
  [[ "$default" == "y" ]] && prompt="[Y/n]" || prompt="[y/N]"
  read -r -p "$question $prompt " reply || reply=""
  reply="${reply,,}"
  if [[ -z "$reply" ]]; then [[ "$default" == "y" ]]; return; fi
  [[ "$reply" == "y" || "$reply" == "yes" ]]
}

# Destructive actions: the user has to type a phrase. Never auto-confirmed by --yes.
confirm_phrase() {
  local phrase="$1" reply
  [[ -t 0 ]] || die "This action requires an interactive confirmation."
  read -r -p "Type '$phrase' to confirm: " reply || reply=""
  [[ "$reply" == "$phrase" ]]
}

# Random hex secret of N bytes (2N hex chars) from the kernel CSPRNG.
gen_secret() { head -c "${1:-32}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# --- .env handling (parsed, never sourced: no code execution from the file) --------------------
env_file() { printf '%s/.env' "${INSTALL_DIR:?}"; }

env_get() { # env_get KEY [file]  (surrounding quotes are removed)
  local key="$1" file="${2:-$(env_file)}" line v
  [[ -f "$file" ]] || return 1
  line="$(grep -E "^${key}=" "$file" | tail -n1)" || return 1
  v="${line#*=}"
  v="${v%$'\r'}"
  if [[ ${#v} -ge 2 && ( "${v:0:1}" == "'" || "${v:0:1}" == '"' ) && "${v: -1}" == "${v:0:1}" ]]; then
    v="${v:1:${#v}-2}"
  fi
  printf '%s' "$v"
}

env_set() { # env_set KEY VALUE (keeps file mode); only "safe" values, no quoting needed
  local key="$1" value="$2" file tmp
  file="$(env_file)"
  [[ "$value" =~ ^[A-Za-z0-9._:/@,+=-]*$ ]] || die "Invalid value for $key (forbidden characters)."
  if grep -qE "^${key}=" "$file" 2>/dev/null; then
    tmp="$(mktemp "${file}.XXXXXX")"
    chmod 600 "$tmp"
    awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="} $1==k {print k"="v; next} {print}' "$file" >"$tmp"
    mv -f "$tmp" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

# --- versions ------------------------------------------------------------------------------------
valid_version() { [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# version_gt A B -> 0 if A is newer than B
version_gt() {
  [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$1" ]]
}

installed_version() { tr -d '[:space:]' <"${INSTALL_DIR:?}/VERSION" 2>/dev/null || true; }

# --- download and integrity ---------------------------------------------------------------------
download() { # download URL FILE
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 300 \
    -H "User-Agent: domainscope-installer" -o "$2" "$1"
}

sha256_of() { sha256sum -- "$1" | awk '{print $1}'; }

# verify_sha256 FILE EXPECTED_HEX
verify_sha256() {
  [[ "$2" =~ ^[0-9a-fA-F]{64}$ ]] || die "Invalid SHA-256 value."
  [[ "$(sha256_of "$1")" == "${2,,}" ]] || die "Checksum mismatch for $(basename "$1") - the file is corrupt or has been tampered with."
}

# Newest release tag of the GitHub repository (plain X.Y.Z)
latest_release_version() {
  local tmp tag
  tmp="$(mktemp)"
  if ! download "https://api.github.com/repos/${DS_REPO}/releases/latest" "$tmp"; then rm -f "$tmp"; return 1; fi
  tag="$(grep -m1 '"tag_name"' "$tmp" | cut -d'"' -f4)"
  rm -f "$tmp"
  tag="${tag#v}"
  valid_version "$tag" || return 1
  printf '%s' "$tag"
}

release_asset_url() { printf 'https://github.com/%s/releases/download/%s/%s' "$DS_REPO" "$1" "$2"; }

# Refuse archives with absolute paths, parent references or special files.
check_archive_safe() {
  local f="$1"
  tar -tzf "$f" >/dev/null 2>&1 || die "The archive is not a valid .tar.gz file."
  if tar -tzf "$f" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
    die "The archive contains unsafe paths."
  fi
  if tar -tvzf "$f" | grep -qE '^[^-d]'; then
    die "The archive contains links or special files."
  fi
}

# --- web user, permissions ----------------------------------------------------------------------
web_user() {
  local u="${DS_WEB_USER:-$DS_WEB_USER_DEFAULT}"
  id "$u" >/dev/null 2>&1 && { printf '%s' "$u"; return; }
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { id -un; return; }
  die "Web server user '$u' does not exist. Set DS_WEB_USER=<user>."
}

# Code root:<web group> read-only, storage/ writable for the web user, .env readable only for root and the web group.
apply_permissions() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || return 0
  local wu; wu="$(web_user)"
  chown -R "root:$wu" "$INSTALL_DIR"
  find "$INSTALL_DIR" -path "$INSTALL_DIR/storage" -prune -o -type d -exec chmod 750 {} +
  find "$INSTALL_DIR" -path "$INSTALL_DIR/storage" -prune -o -type f -exec chmod 640 {} +
  chmod 750 "$INSTALL_DIR"/bin/*.php 2>/dev/null || true
  mkdir -p "$INSTALL_DIR"/storage/{cache,logs,reports,sessions,data}
  chown -R "$wu:$wu" "$INSTALL_DIR/storage"
  find "$INSTALL_DIR/storage" -type d -exec chmod 750 {} +
  find "$INSTALL_DIR/storage" -type f -exec chmod 640 {} +
  [[ -f "$INSTALL_DIR/.env" ]] && chmod 640 "$INSTALL_DIR/.env" && chown "root:$wu" "$INSTALL_DIR/.env"
  return 0
}

# Run a PHP CLI script of the installation as the web user (so created files belong to it).
run_php() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]] && have runuser; then
    runuser -u "$(web_user)" -- php "$@"
  else
    php "$@"
  fi
}

# --- database ------------------------------------------------------------------------------------
# Temporary client option file so that the password never appears on a command line.
# db_defaults_file -> prints the path (caller removes it)
db_defaults_file() {
  local f pass
  f="$(mktemp)"; chmod 600 "$f"
  pass="$(env_get DB_PASS || true)"; pass="${pass//\\/\\\\}"; pass="${pass//\"/\\\"}"
  {
    echo "[client]"
    echo "host=$(env_get DB_HOST || echo 127.0.0.1)"
    echo "port=$(env_get DB_PORT || echo 3306)"
    echo "user=$(env_get DB_USER || true)"
    echo "password=\"$pass\""
    echo "default-character-set=utf8mb4"
  } >"$f"
  printf '%s' "$f"
}

db_client() { have mariadb && echo mariadb || echo mysql; }
db_dump_client() { have mariadb-dump && echo mariadb-dump || echo mysqldump; }

# db_dump OUTFILE.sql.gz
db_dump() {
  local out="$1" cnf name
  name="$(env_get DB_NAME)"; [[ -n "$name" ]] || die "DB_NAME is not set in .env."
  have "$(db_dump_client)" || die "mysqldump/mariadb-dump is not installed (package mariadb-client)."
  cnf="$(db_defaults_file)"
  if ! "$(db_dump_client)" --defaults-extra-file="$cnf" --single-transaction --routines --default-character-set=utf8mb4 "$name" | gzip -9 >"$out"; then
    rm -f "$cnf" "$out"; return 1
  fi
  rm -f "$cnf"
  chmod 600 "$out"
}

# db_restore FILE.sql.gz  - drops all tables of the database first, then imports the dump
db_restore() {
  local in="$1" cnf name tables
  name="$(env_get DB_NAME)"; [[ -n "$name" ]] || die "DB_NAME is not set in .env."
  cnf="$(db_defaults_file)"
  tables="$("$(db_client)" --defaults-extra-file="$cnf" -N -B -e "SELECT CONCAT('DROP TABLE IF EXISTS \`', table_name, '\`;') FROM information_schema.tables WHERE table_schema='${name}' AND table_type='BASE TABLE'")" || { rm -f "$cnf"; return 1; }
  {
    echo "SET FOREIGN_KEY_CHECKS=0;"
    printf '%s\n' "$tables"
    echo "SET FOREIGN_KEY_CHECKS=1;"
  } | "$(db_client)" --defaults-extra-file="$cnf" "$name" || { rm -f "$cnf"; return 1; }
  gunzip -c "$in" | "$(db_client)" --defaults-extra-file="$cnf" "$name" || { rm -f "$cnf"; return 1; }
  rm -f "$cnf"
}

# --- code tree ------------------------------------------------------------------------------------
# Paths that belong to the installation and are never overwritten or deleted by an update.
SYNC_EXCLUDES=(
  --exclude=/.env
  --exclude=/vendor/
  --exclude=/storage/cache/
  --exclude=/storage/logs/
  --exclude=/storage/reports/
  --exclude=/storage/sessions/
  --exclude=/storage/devdb/
  --exclude=/storage/update.lock
)

# sync_tree SRC_DIR DEST_DIR  (mirror, keeps the paths above)
sync_tree() {
  have rsync || die "rsync is required (apt install rsync)."
  rsync -a --delete "${SYNC_EXCLUDES[@]}" -- "${1%/}/" "${2%/}/"
}

# --- backups --------------------------------------------------------------------------------------
# create_backup LABEL -> prints the backup directory
#   <dir>/db.sql.gz, <dir>/app.tar.gz (code + storage/data), <dir>/env, <dir>/VERSION
create_backup() {
  local label="$1" base dir
  base="${DS_BACKUP_DIR:-$DS_DEFAULT_BACKUP_DIR}"
  umask 077
  mkdir -p "$base"; chmod 700 "$base"
  dir="$base/domainscope-$(date +%Y%m%d-%H%M%S)-${label}"
  mkdir -p "$dir"
  db_dump "$dir/db.sql.gz" || { rm -rf "$dir"; die "Database backup failed."; }
  tar -czf "$dir/app.tar.gz" -C "$INSTALL_DIR" \
    --exclude=./storage/cache --exclude=./storage/logs --exclude=./storage/sessions --exclude=./storage/reports \
    --exclude=./storage/devdb --exclude=./vendor --exclude=./.env . || { rm -rf "$dir"; die "Code backup failed."; }
  cp -p "$INSTALL_DIR/.env" "$dir/env"
  installed_version >"$dir/VERSION"
  chmod 600 "$dir"/*
  printf '%s' "$dir"
}

# prune_backups KEEP -> keep the newest KEEP backups
prune_backups() {
  local keep="${1:-10}" base="${DS_BACKUP_DIR:-$DS_DEFAULT_BACKUP_DIR}" d i=0
  [[ "$keep" =~ ^[0-9]+$ && "$keep" -ge 1 ]] || return 0
  while IFS= read -r d; do
    i=$((i + 1))
    [[ $i -gt $keep ]] && rm -rf -- "$d"
  done < <(find "$base" -maxdepth 1 -type d -name 'domainscope-*' | sort -r)
  return 0
}

# --- cron / web server snippets -------------------------------------------------------------------
CRON_FILE="/etc/cron.d/domainscope"

write_cron() {
  local wu php; wu="$(web_user)"; php="$(command -v php)"
  cat >"$CRON_FILE" <<EOF
# DomainScope - written by install.sh
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0,30 * * * * $wu $php $INSTALL_DIR/bin/cron.php --quiet
15 3 * * * $wu $php $INSTALL_DIR/bin/cron.php --quiet --subdomains
EOF
  chmod 644 "$CRON_FILE"
}

#!/usr/bin/env bash
# DomainScope - installer for Debian / Ubuntu.
#
#   tar -xzf domainscope-X.Y.Z.tar.gz && cd domainscope-X.Y.Z && sudo ./install.sh
#
# Installs the code into /var/www/domainscope, creates the database and the login, runs the migrations,
# sets up the cron job and (optionally) a web server virtual host. Run './install.sh --help' for all options.
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SRC_DIR="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
INSTALL_DIR=""
# shellcheck source=scripts/lib.sh
source "$SRC_DIR/scripts/lib.sh"
INSTALL_DIR="$DS_DEFAULT_INSTALL_DIR"

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]
  --dir PATH                 installation directory (default: /var/www/domainscope)
  --domain NAME              host name for the virtual host and APP_URL (default: server IP / localhost)
  --webserver nginx|apache|none   configure a virtual host (default: the installed one, else nginx; --install-deps installs it)
  --https                    the site is served over HTTPS (sets FORCE_HTTPS=1; certificate: see the manual)
  --install-deps             install missing packages with apt (PHP, web server, MariaDB, rsync)
  --db-host HOST             use an existing database server instead of a local MariaDB
  --db-port PORT             (default 3306)
  --db-name NAME             (default domainscope)
  --db-user NAME             (default domainscope)
  --db-pass-file FILE        file with the database password (mandatory with --db-host; the database and user must exist)
  --admin-user NAME          login name (default admin)
  --admin-password-file FILE file with the password (min. 12 characters); otherwise it is asked for, or generated with --yes
  --no-cron                  do not create /etc/cron.d/domainscope
  -y, --yes                  answer questions with "yes"
  --non-interactive          no questions
  -h, --help
EOF
}

DOMAIN=""; WEBSERVER="auto"; HTTPS=0; INSTALL_DEPS=0
DB_HOST_OPT=""; DB_PORT_OPT=3306; DB_NAME_OPT=domainscope; DB_USER_OPT=domainscope; DB_PASS_FILE=""
ADMIN_USER=admin; ADMIN_PASS_FILE=""; NO_CRON=0; ASSUME_YES=0; NON_INTERACTIVE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) INSTALL_DIR="${2:?}"; shift ;;
    --domain) DOMAIN="${2:?}"; shift ;;
    --webserver) WEBSERVER="${2:?}"; shift ;;
    --https) HTTPS=1 ;;
    --install-deps) INSTALL_DEPS=1 ;;
    --db-host) DB_HOST_OPT="${2:?}"; shift ;;
    --db-port) DB_PORT_OPT="${2:?}"; shift ;;
    --db-name) DB_NAME_OPT="${2:?}"; shift ;;
    --db-user) DB_USER_OPT="${2:?}"; shift ;;
    --db-pass-file) DB_PASS_FILE="${2:?}"; shift ;;
    --admin-user) ADMIN_USER="${2:?}"; shift ;;
    --admin-password-file) ADMIN_PASS_FILE="${2:?}"; shift ;;
    --no-cron) NO_CRON=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

main() {
  require_root
  [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" ]] || die "--dir must be an absolute path."
  [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]*$ ]] || die "Invalid --domain."
  [[ "$DB_NAME_OPT" =~ ^[A-Za-z0-9_]+$ && "$DB_USER_OPT" =~ ^[A-Za-z0-9_]+$ ]] || die "Database and user name may only contain letters, digits and underscore."
  [[ "$DB_PORT_OPT" =~ ^[0-9]+$ ]] || die "Invalid --db-port."
  [[ "$ADMIN_USER" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || die "Invalid --admin-user."
  case "$WEBSERVER" in auto|nginx|apache|none) ;; *) die "--webserver must be nginx, apache or none." ;; esac
  [[ -f "$SRC_DIR/bin/migrate.php" && -f "$SRC_DIR/VERSION" ]] || die "Run install.sh from the extracted release directory."
  [[ ! -e "$INSTALL_DIR/.env" ]] || die "$INSTALL_DIR already contains an installation. Use update.sh to update it."
  [[ -z "$DB_HOST_OPT" || -n "$DB_PASS_FILE" ]] || die "--db-host needs --db-pass-file (database and user must already exist)."

  local version; version="$(tr -d '[:space:]' <"$SRC_DIR/VERSION")"
  info "Installing DomainScope $version into $INSTALL_DIR"

  [[ -f /etc/os-release ]] && . /etc/os-release || true
  have apt-get || [[ "$INSTALL_DEPS" -eq 0 ]] || die "--install-deps needs apt (Debian/Ubuntu)."

  install_dependencies
  check_php

  # ---- code -------------------------------------------------------------------------------
  mkdir -p "$INSTALL_DIR"
  if [[ "$(readlink -f "$SRC_DIR")" != "$(readlink -f "$INSTALL_DIR")" ]]; then
    have rsync || die "rsync is required (apt install rsync, or use --install-deps)."
    rsync -a --exclude=/.git/ --exclude=/install.sh.bak -- "$SRC_DIR/" "$INSTALL_DIR/"
  fi

  # ---- .env and database -----------------------------------------------------------------------
  cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"; chmod 600 "$INSTALL_DIR/.env"
  local db_pass db_host="127.0.0.1"
  if [[ -n "$DB_HOST_OPT" ]]; then
    db_host="$DB_HOST_OPT"
    db_pass="$(head -n1 "$DB_PASS_FILE" | tr -d '\r\n')"
    [[ -n "$db_pass" ]] || die "The database password file is empty."
  else
    db_pass="$(gen_secret 16)"
    create_local_database "$db_pass"
  fi
  env_set DB_HOST "$db_host"; env_set DB_PORT "$DB_PORT_OPT"; env_set DB_NAME "$DB_NAME_OPT"; env_set DB_USER "$DB_USER_OPT"
  [[ "$db_pass" =~ ^[A-Za-z0-9._:/@,+=-]+$ ]] || die "The database password contains characters that cannot be stored safely in .env (allowed: letters, digits and . _ : / @ , + = -)."
  env_set DB_PASS "$db_pass"
  env_set APP_ENV production; env_set APP_DEBUG 0
  env_set FORCE_HTTPS "$HTTPS"
  local scheme=http; [[ "$HTTPS" -eq 1 ]] && scheme=https
  env_set APP_URL "$scheme://${DOMAIN:-localhost}"

  # ---- login --------------------------------------------------------------------------------------
  local pwfile generated=""; pwfile="$(mktemp)"; chmod 600 "$pwfile"
  # shellcheck disable=SC2064
  trap "rm -f '$pwfile'" EXIT
  if [[ -n "$ADMIN_PASS_FILE" ]]; then
    head -n1 "$ADMIN_PASS_FILE" >"$pwfile"
  elif [[ "$NON_INTERACTIVE" -eq 0 && -t 0 && "$ASSUME_YES" -eq 0 ]]; then
    local p1 p2
    read -r -s -p "Password for '$ADMIN_USER' (min. 12 characters): " p1; echo
    read -r -s -p "Repeat: " p2; echo
    [[ "$p1" == "$p2" ]] || die "The passwords do not match."
    printf '%s\n' "$p1" >"$pwfile"
  else
    generated="$(gen_secret 10)"
    printf '%s\n' "$generated" >"$pwfile"
  fi
  (cd "$INSTALL_DIR" && php bin/setup.php "--user=$ADMIN_USER" "--password-file=$pwfile") >/dev/null || die "Setting up the login failed (password at least 12 characters?)."

  # ---- schema -------------------------------------------------------------------------------------
  apply_permissions
  info "Creating the database schema"
  (cd "$INSTALL_DIR" && run_php bin/migrate.php) || die "Migrations failed."
  run_php "$INSTALL_DIR/bin/health.php" || die "The self-test failed (see above)."

  [[ "$NO_CRON" -eq 1 ]] || { write_cron; ok "Cron job installed ($CRON_FILE)"; }
  configure_webserver
  apply_permissions

  ok "DomainScope $version is installed."
  echo
  echo "  Address:   $scheme://${DOMAIN:-<server address>}/"
  echo "  Login:     $ADMIN_USER"
  [[ -n "$generated" ]] && echo "  Password:  $generated   (generated - change it under 'Konto & Sicherheit'; shown only once)"
  echo "  Directory: $INSTALL_DIR   (configuration: $INSTALL_DIR/.env)"
  echo
  echo "  Next steps: enable HTTPS (see docs/MANUAL.md) and set up two-factor authentication."
  echo "  Update later with: sudo $INSTALL_DIR/update.sh"
}

install_dependencies() {
  local missing=()
  have php || missing+=(php-cli)
  have rsync || missing+=(rsync)
  have curl || missing+=(curl)
  if [[ "$INSTALL_DEPS" -eq 1 ]]; then
    local ws="$WEBSERVER"
    if [[ "$ws" == "auto" ]]; then
      if have nginx; then ws=nginx; elif have apache2; then ws=apache; else ws=nginx; fi
    fi
    missing+=(php-fpm php-curl php-mbstring php-mysql)
    [[ -z "$DB_HOST_OPT" ]] && missing+=(mariadb-server)
    case "$ws" in nginx) missing+=(nginx) ;; apache) missing+=(apache2) ;; esac
    info "Installing packages: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}"
  elif [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing: ${missing[*]}. Install them or run with --install-deps."
  fi
}

check_php() {
  have php || die "PHP is not installed."
  php -r 'exit(PHP_VERSION_ID >= 80400 ? 0 : 1);' || die "PHP 8.4 or newer is required (found $(php -r 'echo PHP_VERSION;')). Debian 13 ships PHP 8.4; on Ubuntu 24.04 use a PHP 8.4 package source such as ondrej/php."
  local ext
  for ext in curl openssl pdo_mysql mbstring json; do
    php -m | grep -qix "$ext" || die "PHP extension '$ext' is missing (apt install php-${ext/pdo_mysql/mysql})."
  done
}

create_local_database() {
  local pass="$1" client
  client="$(db_client)"
  have "$client" || die "MariaDB/MySQL client not found (use --install-deps)."
  systemctl is-active --quiet mariadb 2>/dev/null || systemctl is-active --quiet mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || systemctl start mysql 2>/dev/null || true
  info "Creating database '$DB_NAME_OPT' and user '$DB_USER_OPT'"
  "$client" <<SQL || die "Could not create the database (root access over the socket is required)."
CREATE DATABASE IF NOT EXISTS \`$DB_NAME_OPT\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER_OPT'@'localhost' IDENTIFIED BY '$pass';
ALTER USER '$DB_USER_OPT'@'localhost' IDENTIFIED BY '$pass';
GRANT ALL PRIVILEGES ON \`$DB_NAME_OPT\`.* TO '$DB_USER_OPT'@'localhost';
FLUSH PRIVILEGES;
SQL
}

fpm_socket() {
  local s
  for s in /run/php/php*-fpm.sock; do [[ -S "$s" ]] && { printf '%s' "$s"; return; }; done
  return 1
}

configure_webserver() {
  local ws="$WEBSERVER"
  if [[ "$ws" == "auto" ]]; then
    if have nginx; then ws=nginx; elif have apache2; then ws=apache; else ws=none; fi
  fi
  [[ "$ws" == "none" ]] && { warn "No web server configured. Point your web server at $INSTALL_DIR/public (see docs/MANUAL.md)."; return; }
  local sock name="${DOMAIN:-_}"
  sock="$(fpm_socket)" || { warn "No PHP-FPM socket found - skipping the virtual host (see docs/MANUAL.md)."; return; }

  if [[ "$ws" == "nginx" ]]; then
    have nginx || die "nginx is not installed (use --install-deps)."
    local conf=/etc/nginx/sites-available/domainscope
    [[ ! -e "$conf" ]] || { warn "$conf already exists - not overwritten."; return; }
    cat >"$conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $name;
    root $INSTALL_DIR/public;
    index index.php;

    location / { try_files \$uri /index.php\$is_args\$args; }
    location ~ \.php\$ {
        try_files /index.php =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root/index.php;
        fastcgi_pass unix:$sock;
    }
    location ~ /\.(?!well-known) { deny all; }
}
EOF
    ln -sf "$conf" /etc/nginx/sites-enabled/domainscope
    nginx -t 2>&1 && systemctl reload nginx && ok "nginx virtual host created ($conf)"
  else
    have apache2 || die "Apache is not installed (use --install-deps)."
    local conf=/etc/apache2/sites-available/domainscope.conf fpmconf
    [[ ! -e "$conf" ]] || { warn "$conf already exists - not overwritten."; return; }
    a2enmod -q rewrite proxy_fcgi setenvif headers
    fpmconf="$(basename "$sock" .sock)"; fpmconf="${fpmconf%-fpm}-fpm"
    a2enconf -q "$fpmconf" 2>/dev/null || true
    cat >"$conf" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN:-localhost}
    DocumentRoot $INSTALL_DIR/public
    <Directory $INSTALL_DIR/public>
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch "\.php\$">
        SetHandler "proxy:unix:$sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
EOF
    a2ensite -q domainscope
    apache2ctl configtest 2>&1 && systemctl reload apache2 && ok "Apache virtual host created ($conf)"
  fi
}

main "$@"
exit $?

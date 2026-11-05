# DomainScope manual

1. [Requirements](#requirements)
2. [Installation](#installation)
   ([updates](#updating-domainscope), [backup and restore](#backup-and-restore), [uninstall](#uninstall), [HTTPS](#https))
3. [Configuration](#configuration)
4. [Database migrations](#database-migrations)
5. [Cron jobs](#cron-jobs)
6. [Deployment](#deployment)
7. [Operating it responsibly](#operating-it-responsibly)
8. [Tests](#tests)
9. [Architecture](#architecture)
10. [Data sources](#data-sources)
11. [Known limitations](#known-limitations)
12. [Troubleshooting](#troubleshooting)

## Requirements

- **PHP ≥ 8.4** (tested with 8.5) with `curl`, `openssl`, `pdo_mysql`, `mbstring`, `json`. `intl` is **not** needed (Punycode/IDN are implemented in PHP).
- **MySQL 8** or **MariaDB ≥ 10.4**.
- Apache or Nginx with PHP-FPM, or the PHP development server for local use.
- Outgoing connections: HTTPS (443) to DoH resolvers, RDAP servers and CT sources; optionally TCP 43 (WHOIS), UDP/TCP 53 (authoritative
  name servers for the delegation check), TCP 25 (STARTTLS test, off by default).
- Composer is only needed for the tests.

## Installation

### With the installer (Debian / Ubuntu)

Download a release, verify its checksum and run `install.sh` as root (see the [README](../README.md#installation)):

```bash
tar -xzf domainscope-X.Y.Z.tar.gz && cd domainscope-X.Y.Z
sudo ./install.sh --install-deps --domain domainscope.example.org
```

What it does: checks PHP ≥ 8.4 and the extensions; with `--install-deps` installs `php-fpm`, the PHP extensions, `mariadb-server` and nginx
(or Apache with `--webserver apache`); copies the code to `/var/www/domainscope` (`--dir`); creates the database and a database user with a
generated password (or uses an existing server with `--db-host` and `--db-pass-file`); writes `.env`; sets up the login (asked for, from
`--admin-password-file`, or generated and shown once); runs the migrations and `bin/health.php`; creates `/etc/cron.d/domainscope`
(every 30 minutes and a daily subdomain scan, run as the web user); creates a virtual host. Existing files are never overwritten.

Permissions: the code belongs to `root:www-data` and is read-only for the web server; only `storage/` is writable for it; `.env` is `640`.
Options: `./install.sh --help` (`--https` sets `FORCE_HTTPS=1`, `--no-cron`, `--non-interactive`, `-y`).

On Ubuntu 24.04 PHP 8.3 is the default; install PHP 8.4 from a package source such as `ondrej/php` first.

### HTTPS

The installer creates an HTTP virtual host. Add a certificate, for example with Certbot (`sudo certbot --nginx -d domainscope.example.org`), then
set `FORCE_HTTPS=1` and `APP_URL=https://…` in `.env`. Do not use the application over plain HTTP outside a trusted network.

### Manual installation (development)

```bash
git clone https://github.com/cberthun/DomainScope.git domainscope && cd domainscope
php bin/setup.php            # creates .env, APP_KEY and the password hash (asks for user name and password)
# set DB_HOST, DB_NAME, DB_USER, DB_PASS in .env and create the database:
#   CREATE DATABASE domainscope CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
#   CREATE USER 'domainscope'@'localhost' IDENTIFIED BY '…';
#   GRANT ALL ON domainscope.* TO 'domainscope'@'localhost';
php bin/migrate.php          # create the schema
php -S 127.0.0.1:8080 -t public
```

Without a configured password the application refuses every request (page “Einrichtung erforderlich”). `php bin/health.php` checks the setup.

### Updating the bundled data

The files in `storage/data/` work offline. The RDAP bootstrap is refreshed automatically when it is older than 7 days. The Public Suffix
List and the CA bundle can be replaced when needed:

```bash
curl -fL https://publicsuffix.org/list/public_suffix_list.dat -o storage/data/public_suffix_list.dat
curl -fL https://curl.se/ca/cacert.pem -o storage/data/cacert.pem
```

### Updating DomainScope

```bash
sudo /var/www/domainscope/update.sh --check     # installed and available version
sudo /var/www/domainscope/update.sh             # update to the latest release
sudo /var/www/domainscope/update.sh --version 1.1.0
sudo /var/www/domainscope/update.sh --file domainscope-1.1.0.tar.gz --sha256 <hash>    # offline
```

Flow: download of `domainscope-<version>.tar.gz` and `.sha256` from the GitHub release → checksum check → safety checks of the archive
(no absolute paths, `..` or links; no downgrade without `--allow-downgrade`) → **backup** (database, code, `.env`) → copy the new files →
migrations → `bin/health.php` and a request to `APP_URL/login` → on any error an **automatic rollback** (code, and the database if migrations had run).
`.env`, `vendor/` and the runtime data in `storage/` (cache, logs, reports, sessions) are never touched; the bundled data files in
`storage/data/` are replaced by the release's versions. Read the [CHANGELOG](../CHANGELOG.md) first. The update does not run by itself: you decide when.

The updater keeps the 10 newest backups in `/var/backups/domainscope` (`--keep N`).

## Backup and restore

```bash
sudo /var/www/domainscope/backup.sh                       # → /var/backups/domainscope/domainscope-<time>-manual/
sudo /var/www/domainscope/restore.sh /var/backups/domainscope/domainscope-<time>-<label>   # --code-only | --db-only
```

A backup holds `db.sql.gz`, `app.tar.gz` (code and bundled data), `env` and `VERSION`. It contains **secrets** (`.env`, password hash): keep
the directory private (mode 0700) and copy backups off the server. `restore.sh` makes a safety backup of the current state first.

## Uninstall

```bash
sudo /var/www/domainscope/uninstall.sh [--drop-database]
```

Makes a final backup (kept), removes the cron job, the virtual host and the directory. The database is only dropped with `--drop-database`
and only if it is on the same server. You have to type a confirmation phrase.

## Configuration

Configuration lives in `.env` (never commit it; `chmod 600`). Start from `.env.example`.

| Variable | Meaning |
| --- | --- |
| `APP_ENV`, `APP_DEBUG` | `production` / `development`; debug shows error details (local use only!) |
| `APP_URL`, `APP_TIMEZONE` | Base URL and display time zone (the database stores UTC) |
| `APP_KEY` | Random secret (created by `bin/setup.php`) |
| `AUTH_USERNAME`, `AUTH_PASSWORD_HASH` | Login (Argon2id/bcrypt) – set only through `php bin/setup.php` |
| `AUTH_IP_ALLOWLIST` | Optional comma-separated list of addresses allowed to connect |
| `SESSION_IDLE_TIMEOUT` | Idle timeout in seconds (default 3600) |
| `FORCE_HTTPS` | `1` enforces HTTPS redirect, secure cookies and HSTS |
| `TRUSTED_PROXY` | Address of a reverse proxy whose `X-Forwarded-For/Proto` is trusted |
| `HTTP_CONTACT` | Optional contact (URL or email) appended to the `User-Agent` of outgoing requests |
| `DB_*` | Database connection |

Runtime settings (warning thresholds for certificates and domains, cache duration, WHOIS fallback, DKIM selector scan, default selectors, …)
are in the interface under **Einstellungen** (table `application_settings`).

The password can be changed under **Konto & Sicherheit** (or with `php bin/setup.php`). Two-factor authentication is set up there as well
(enter the key manually in an authenticator app; there is no QR code because no library is bundled).
**Do not change `APP_KEY` after enabling 2FA**, otherwise the TOTP secret becomes unreadable (emergency: delete the row in `auth_credentials`).

## Database migrations

```bash
php bin/migrate.php            # apply missing migrations
php bin/migrate.php --status   # show status
```

Migrations are applied by `update.sh` automatically. They are SQL files in `database/migrations/` and tracked in the table `schema_migrations`.

## Cron jobs

Checks run only from the CLI (`bin/cron.php` exits at once when called through the web server; there is no public cron URL).

```cron
# every 30 minutes: re-check monitored domains whose last check is older than 6 hours
0,30 * * * * /usr/bin/php /var/www/domainscope/bin/cron.php --quiet
# daily: additionally run passive subdomain scans
15 3 * * * /usr/bin/php /var/www/domainscope/bin/cron.php --quiet --subdomains
```

Options: `--interval=HOURS` (default 6), `--force`, `--domain=example.com`, `--modules=dns,email,tls,dnssec,http,ips,registration,subdomains`,
`--subdomains`, `--quiet`. Mark domains for monitoring in the domain detail view or under *Monitoring*. Registration data (RDAP/WHOIS) is
fetched at most every 24 hours. Parallel runs are prevented by a lock file (`storage/cron.lock`, not versioned).

## Deployment

1. Put the code on the server; expose **only** `public/` as the web root.
2. Create `.env` with `chmod 600` (`php bin/setup.php`) and set `FORCE_HTTPS=1` behind TLS.
3. `storage/` must be writable for the PHP user (`cache`, `logs`, `sessions`, `reports`) and must **not** be reachable from the web.
4. Run `php bin/migrate.php`, then set up the cron job.
5. Restrict access further: `AUTH_IP_ALLOWLIST`, a VPN, or HTTP authentication of the web server.

**Apache**

```apache
<VirtualHost *:443>
    ServerName domainscope.example.org
    DocumentRoot /var/www/domainscope/public
    <Directory /var/www/domainscope/public>
        AllowOverride All
        Require all granted
    </Directory>
    # SSLEngine on … (certificate)
</VirtualHost>
```

`public/.htaccess` routes all non-file requests to `index.php`; the `.htaccess` in the project root denies everything if the directory is
served by mistake.

**Nginx + PHP-FPM**

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name domainscope.example.org;
    root /var/www/domainscope/public;
    index index.php;

    location / { try_files $uri /index.php$is_args$args; }
    location ~ \.php$ {
        try_files /index.php =404;      # only the front controller may run
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }
    location ~ /\.(?!well-known) { deny all; }
}
```

## Operating it responsibly

- Analyse only domains you own or are authorised to assess.
- Set `HTTP_CONTACT` so that operators of the queried services can reach you.
- Keep the cron interval reasonable. Registration data is fetched at most daily; CT sources (crt.sh, Cert Spotter) are rate-limited and sometimes
  overloaded – partial failures are shown and never turn into “no longer found”.
- The STARTTLS test and active HTTP checks are limited to hosts of your domains and can be switched off in the settings.
- Do not make the instance publicly usable as a lookup service for third parties: it is a single-user tool without rate limiting per visitor,
  and every lookup is sent to third-party services under your address.
- Back up the database. It holds the history, findings and your inventory.

## Tests

```bash
composer install
vendor/bin/phpunit
```

- **Unit tests** (`tests/Unit`): domain/IDN/IP validation, DNS parsing and status handling, SPF/DKIM/DMARC/MTA-STS/TLS-RPT, RDAP/WHOIS,
  TLS certificate checks, DNSSEC (with a fixture of real cloudflare.com data), findings rules, access protection, CSRF, SSRF (including
  redirect and rebinding scenarios), timeouts and error handling. External services are mocked.
- **Integration tests** (`tests/Integration`): migrations, database access, transactions, snapshots and diffs, findings life cycle,
  subdomain comparison, end-to-end flows, HTML escaping.
- Database tests use **their own** database (`TEST_DB_NAME`, default `domainscope_test`) and **empty its tables**. If it is unreachable the
  tests are skipped. The `.env` user needs privileges on that database.

## Architecture

```
public/            front controller (index.php), assets/ (CSS, JS, SVG)
app/
  Controllers/     thin controllers per area
  Services/        DNS (DoH, raw UDP/TCP), RDAP, WHOIS, Subdomains, IPIntelligence,
                   TLS, EmailSecurity, DNSSEC, Http (SafeHttp with SSRF protection), Reports
  Repositories/    PDO access (prepared statements)
  Findings/        FindingsEngine (documented rules)
  Jobs/            ModuleRunner (check → store → changes → findings)
  Security/        Auth, Session, CSRF, TOTP
  Validation/      Punycode, domain name, public suffix, IP classification, input analysis
  Support/         router, request/response, view, config, settings, logger, cache, migrator
  Views/           layouts, pages, partials (server-rendered HTML)
bin/               setup.php, migrate.php, cron.php (CLI only)
config/            app.php, database.php
database/          migrations/
storage/           cache, logs, sessions, reports, data (PSL, RDAP bootstrap, CA bundle)
tests/             Unit, Integration, fixtures
```

Long-running checks run as AJAX POST (`fetch`) and update only the active tab; without JavaScript all pages work as plain forms and links.
User-visible text in the interface is German.

## Data sources

| Purpose | Source |
| --- | --- |
| DNS | DNS-over-HTTPS JSON: Cloudflare (`cloudflare-dns.com`), Google (`dns.google`), Quad9 (`dns.quad9.net:5053`) |
| Delegation / DNSSEC | direct UDP/TCP queries to authoritative name servers (public addresses only) |
| Registration | RDAP via the [IANA bootstrap](https://data.iana.org/rdap/) (plus `rdap.denic.de` for `.de`); WHOIS fallback via `whois.iana.org` → TLD WHOIS |
| Subdomains | Certificate Transparency: crt.sh, Cert Spotter |
| ASN / BGP | Team Cymru IP-to-ASN (over DNS), RIR RDAP |
| TLS | direct handshake to the hosts |
| MTA-STS / BIMI | HTTPS retrieval of the policy / logo file |

Apart from these technically necessary queries (domain names, IP addresses) no data is sent to third parties.

## Known limitations

- The STARTTLS test needs outgoing port 25, which many providers block (result “unreachable”, not a finding). It only runs on request or
  when enabled in the settings.
- CT alarm and takeover check give indications: DomainScope cannot know who requested a certificate and cannot prove that a takeover is exploitable.
- DKIM selectors cannot be listed through DNS. Only the given selectors (and optionally about 30 common ones) are checked; not finding one proves nothing.
- SPF mechanisms with macros (`exists:%{i}…`) are not resolved.
- DNSSEC: DS↔DNSKEY and the RRSIG of the DNSKEY RRset (RSA/ECDSA) are verified locally; the chain up to the root and other RRsets are only
  confirmed by the resolvers' AD flags. Ed25519/Ed448 signatures are not verified locally.
- RDAP: registrant data is mostly redacted. `.de` returns minimal data over RDAP; WHOIS output is parsed heuristically.
- Quad9 is reachable only if outgoing port 5053 is allowed. The delegation check needs outgoing UDP/TCP 53.
- Time stamps are stored in UTC and shown in `APP_TIMEZONE`. The PHP development server is single-threaded.

## Troubleshooting

| Symptom | Cause / solution |
| --- | --- |
| “Einrichtung erforderlich” | run `php bin/setup.php` |
| HTTP 500 | check `storage/logs/app-*.log` and `php-error.log`; `APP_DEBUG=1` only locally |
| TLS check always says “not trusted” | `storage/data/cacert.pem` missing or outdated |
| DNS queries time out | outgoing HTTPS blocked or resolver unreachable (Dashboard → data sources) |
| Tests are skipped | test database unreachable (`TEST_DB_NAME`, privileges) |
| `openssl_pkey_new` fails in tests (Windows) | set `OPENSSL_CONF` to `php/extras/ssl/openssl.cnf` |

<p align="center">
  <img src="public/assets/images/logo.png" alt="DomainScope" width="96">
</p>

<h1 align="center">DomainScope</h1>

<p align="center">
  A self-hosted dashboard for the domains, DNS, email security and certificates you are responsible for – with history, change detection and findings.
</p>

<p align="center">
  <a href="https://github.com/cberthun/domainscope/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cberthun/domainscope/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE.md"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue"></a>
  <img alt="PHP" src="https://img.shields.io/badge/PHP-8.4%2B-777bb4">
</p>

<p align="center">made with <span>♥️</span> by <a href="https://github.com/cberthun">cberthun</a></p>

---

DomainScope collects the technical state of your domains in one place, stores it as snapshots, notices what changed and turns it into
understandable **findings** with a reason and a recommendation. Plain PHP and MySQL/MariaDB: no framework, no Node.js, no build step,
no telemetry, no external CDNs. The interface is in German; the documentation is in English.

> **Use it on your own domains.** DomainScope queries third-party services and the infrastructure of the domains you enter. Only analyse
> domains you own or are authorised to assess. See [Responsible use](#responsible-use).

## Features

* **DNS explorer**: A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, PTR, NAPTR, DS, DNSKEY over DNS-over-HTTPS (Cloudflare, Google, Quad9), resolver comparison, NXDOMAIN / SERVFAIL / REFUSED / timeout told apart, snapshots and diffs
* **RDAP & WHOIS**: RDAP via the IANA bootstrap, controlled WHOIS fallback, registrar, status, expiry, history
* **Subdomains** (passive): Certificate Transparency (crt.sh, Cert Spotter), de-duplication, scan comparison, **CT alarm** for new certificates, **takeover check** for dangling CNAMEs
* **IP & ASN**: classification, reverse DNS, BGP origin (Team Cymru), registration – no guessed geolocation
* **Email security**: SPF (recursive, lookup and void limits), DKIM, DMARC, MX/PTR/FCrDNS, MTA-STS, TLS-RPT, BIMI, optional STARTTLS test
* **SSL/TLS**: real handshake with SNI, chain, key, protocol, expiry and hostname checks
* **DNSSEC & delegation**: DS↔DNSKEY digest check, local RRSIG verification, parent/child NS comparison, lame delegation; **CAA** and **DANE/TLSA** hardening checks
* **Monitoring**: cron-driven re-checks, change detection, expiry warnings
* **Findings**: rule-based, severities, evidence, recommendation, status and history
* **Inventory** with relationship graph, **reports** as print-optimised HTML, JSON and CSV
* **Account security**: Argon2id login, TOTP two-factor authentication with recovery codes, brute-force lockout, optional IP allow-list

A missing piece of information is never reported as a vulnerability: unreachable sources yield “unknown”, optional features (MTA-STS, BIMI) yield “information”.

## Installation

Requirements: **PHP ≥ 8.4** (`curl`, `openssl`, `pdo_mysql`, `mbstring`, `json`), **MySQL 8 or MariaDB ≥ 10.4**, a web server with PHP-FPM
(or the PHP development server for local use). Composer is only needed for the tests.

```bash
git clone https://github.com/cberthun/domainscope.git && cd domainscope
php bin/setup.php        # creates .env, APP_KEY and the login (asks for user name and password)
# enter the database credentials in .env, then create the database:
#   CREATE DATABASE domainscope CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
php bin/migrate.php      # create the schema
php -S 127.0.0.1:8080 -t public
```

Open <http://127.0.0.1:8080> and sign in. For a production setup (Apache/Nginx, HTTPS, cron jobs, hardening) see the
**[manual](docs/MANUAL.md)**.

> DomainScope is a **single-user** application. Do not expose it to the internet without HTTPS (`FORCE_HTTPS=1`), and preferably put it
> behind a VPN, an IP allow-list (`AUTH_IP_ALLOWLIST`) or HTTP authentication of the web server.

## Responsible use

* Analyse only domains and servers you own or have permission to assess.
* DomainScope performs **no** brute-force enumeration, port scans or exploitation. Active checks (TLS handshake, HTTP requests, STARTTLS)
  are limited to hosts of the domains you added and are triggered explicitly or by your own cron job.
* Third-party services have their own terms and rate limits (crt.sh, Cert Spotter, public DoH resolvers, RDAP/WHOIS servers, Team
  Cymru). Do not run it in a way that hammers them. Outgoing requests identify themselves with a `User-Agent`; set `HTTP_CONTACT` in `.env`
  so that operators can reach you.
* The software is provided without warranty (see [LICENSE](LICENSE.md)). Findings are indications, not proof.

## Development

```bash
composer install
vendor/bin/phpunit
```

Database tests use their own database (`TEST_DB_NAME`, default `domainscope_test`) and **empty its tables**; they are skipped if it is
not reachable. Layout and conventions: [docs/MANUAL.md](docs/MANUAL.md#architecture) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Threat model and measures: [docs/SECURITY.md](docs/SECURITY.md). Please do **not** report vulnerabilities publicly but as described in
[.github/SECURITY.md](.github/SECURITY.md).

## License

DomainScope is free software under the **[GNU Affero General Public License v3.0 or later](LICENSE.md)** (`AGPL-3.0-or-later`). If you run a
modified version as a network service, you must offer its source code to the users of that service. Attribution notices are listed in
[NOTICE.md](NOTICE.md); bundled third-party data is listed in [THIRD_PARTY.md](THIRD_PARTY.md).

---

<p align="center">made with ♥️ by <a href="https://github.com/cberthun">cberthun</a></p>

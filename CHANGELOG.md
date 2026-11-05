# Changelog

All notable changes. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0]

First public release, licensed under the **GNU Affero General Public License v3.0 or later**.

### Changes
- **Open source:** license changed from proprietary to AGPL-3.0-or-later (`LICENSE.md`); added `NOTICE.md` (author attribution under AGPL section 7,
  origin), `THIRD_PARTY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/MANUAL.md`, `docs/SECURITY.md`, `.github/SECURITY.md`, issue and
  pull request templates, Dependabot and a CI workflow (PHPUnit against MariaDB, PHP syntax check, version check).
- **New logo** (magnifier over a globe) in the interface and as favicon.
- Documentation rewritten in English; the interface remains German.
- The `User-Agent` of outgoing requests now contains the version and the project URL; `HTTP_CONTACT` in `.env` adds a contact for operators of queried services.
- Footer shows the author attribution and the license.
- Removed development leftovers from the repository (`PROMPT.md`, reference analysis, editor settings, runtime lock file); `storage/cron.lock` is ignored.

### Features (since the first private version)
- DNS explorer, RDAP/WHOIS, passive subdomain discovery, IP/ASN, email security (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI), SSL/TLS, DNSSEC and delegation checks.
- CT alarm, takeover check, CAA/DANE/STARTTLS hardening checks, password change and TOTP two-factor authentication.
- Monitoring with snapshots and change detection, findings, inventory with graph, reports (HTML, JSON, CSV).

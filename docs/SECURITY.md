# Security

Threat model and measures of DomainScope. To report a vulnerability see [.github/SECURITY.md](../.github/SECURITY.md).

## Model

DomainScope is a **single-user** tool run by the person who is responsible for the analysed domains. The assets worth protecting are the
login, the stored history and inventory, and the server's ability to make outgoing requests. The main risks are:

1. an attacker reaching the login or an authenticated session,
2. server-side request forgery (SSRF) through user-supplied domains, redirects and DNS answers,
3. malicious content in third-party data (DNS, RDAP, WHOIS, HTTP) reaching the browser or the database,
4. misuse of the instance as a scanner against third parties.

## Measures

- **Access:** login (Argon2id/bcrypt), optional TOTP second factor (secret encrypted with AES-256-GCM derived from `APP_KEY`, replay
  protection, single-use recovery codes stored only as hashes), brute-force lockout per address (also for the second factor), idle
  timeout, optional IP allow-list, lock-out when no password is configured.
- **Sessions:** `HttpOnly`, `SameSite=Strict`, `Secure` and `__Host-` prefix over HTTPS, strict mode, ID renewal on login, own session directory.
- **CSRF:** token for all POST actions (form field or `X-CSRF-Token`).
- **SQL:** prepared statements only (native, no emulation).
- **XSS:** consistent HTML escaping; CSP `script-src 'self'` (no inline scripts), `frame-ancestors 'none'`, `nosniff`, `no-referrer`,
  `Cache-Control: no-store`, HSTS over HTTPS.
- **SSRF:** `SafeHttp` allows only http/https on approved ports, resolves host names itself, rejects private, loopback, link-local and reserved
  addresses (including IPv6 and IPv4-mapped), **pins** the connection to the verified address (no DNS rebinding), follows redirects manually and
  checks **every** hop, and limits size, time and redirect depth. The same applies to TLS, WHOIS and raw DNS connections.
- **Third-party data:** DNS, RDAP, WHOIS and HTTP answers are untrusted: strict normalisation, length limits, escaping, never executed;
  CSV exports neutralise formula injection.
- **Files:** fixed paths, hashed cache keys, sanitised download file names.
- **Secrets:** only in `.env`; logs mask passwords and tokens.
- **Scope of active checks:** no brute-force enumeration, no port scans, no exploit functions. Active checks are limited to hosts of your own
  domains, a bounded number, and explicitly triggered.
- **No telemetry, no external frontend resources.**

## Operator checklist

- Serve only `public/`; keep `storage/` and `.env` out of the web root (`chmod 600 .env`).
- Use HTTPS and set `FORCE_HTTPS=1`; set `TRUSTED_PROXY` only to the address of your own reverse proxy.
- Enable two-factor authentication; use a long unique password.
- Restrict access with `AUTH_IP_ALLOWLIST`, a VPN or HTTP authentication.
- Keep PHP and the database updated, and back up the database.
- Set `HTTP_CONTACT` so that operators of queried services can reach you.

## Out of scope

Anyone who can run PHP code on the server or read `.env`, a compromised browser, and denial of service by third-party data sources are outside
the model.

# Third-party components

DomainScope has **no runtime dependencies** besides PHP and its extensions. The following files and services are used or bundled.

## Bundled data (`storage/data/`)

| File | Source | License / terms |
|---|---|---|
| `public_suffix_list.dat` | <https://publicsuffix.org/> (Mozilla Foundation and contributors) | MPL-2.0 |
| `cacert.pem` | <https://curl.se/docs/caextract.html> (Mozilla CA certificate store, extracted by curl) | MPL-2.0 |
| `rdap-dns.json`, `rdap-ipv4.json`, `rdap-ipv6.json`, `rdap-asn.json` | IANA RDAP bootstrap, <https://data.iana.org/rdap/> | IANA terms of use; public registry data |

The files can be replaced by newer versions at any time (see the [manual](docs/MANUAL.md#updating-the-bundled-data)).

## Development dependencies

| Component | Use | License |
|---|---|---|
| PHPUnit 12 and its dependencies (`composer.lock`) | Tests only, not installed in production | BSD-3-Clause (and the licenses of its dependencies) |
| GitHub Actions (`actions/checkout`, `shivammathur/setup-php`) | CI only | MIT |

## External services queried at run time

DomainScope does not bundle these, it only sends requests to them. Their terms and rate limits apply to your use.

| Service | Purpose |
|---|---|
| Cloudflare, Google, Quad9 (DNS-over-HTTPS) | DNS lookups |
| IANA, registry and registrar RDAP servers, WHOIS servers | Registration data |
| crt.sh, Cert Spotter | Certificate Transparency data for passive subdomain discovery |
| Team Cymru IP-to-ASN (DNS) | BGP origin and prefix |
| The hosts you analyse | TLS handshake, MTA-STS policy, BIMI logo, HTTP checks |

No data is sent anywhere else; there is no telemetry and no external frontend resource.

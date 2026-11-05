# Contributing

Thanks for your interest! DomainScope is licensed under the [GNU AGPL v3.0 or later](LICENSE.md) (see also [NOTICE](NOTICE.md)).
By submitting a contribution you confirm that you have the right to submit it and that it is licensed under the same terms.

## Bugs and requests

Open an issue with the version, PHP and database version and a log excerpt (without passwords, tokens or `.env` contents).
**Do not report security vulnerabilities publicly**, see [.github/SECURITY.md](.github/SECURITY.md).

## Pull requests

1. Branch from `main`, keep the change small and self-contained.
2. Run the tests (`composer install && vendor/bin/phpunit`); new logic gets a test. External services are mocked, tests must not need the internet.
3. Follow the existing style: `declare(strict_types=1)`, prepared statements only, everything from DNS/RDAP/WHOIS/HTTP is untrusted, all output escaped.
4. Outgoing requests go through `SafeHttp` (or the existing raw DNS/TLS/WHOIS clients), never straight through `curl`/`file_get_contents`.
5. User-facing text in the interface is German; code, comments for new code, commit messages and documentation are English.
6. Update the documentation and add an entry to `CHANGELOG.md`.
7. Do not copy code, data or text from projects with an incompatible license. When you add a list of values (selectors, patterns), say where it comes from.

## Publishing a release (maintainers)

```bash
echo 1.0.1 > VERSION                  # new version number (SemVer)
# CHANGELOG.md: add a section "## [1.0.1]"
git commit -am "Release 1.0.1" && git push
git tag 1.0.1 && git push origin 1.0.1
```

The tag is the plain version number **without** `v`. CI checks that `VERSION` is valid and has a CHANGELOG section.

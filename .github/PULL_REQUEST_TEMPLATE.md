## What and why

<!-- What does this change, and why is it needed? Link the issue. -->

## Checklist

- [ ] `vendor/bin/phpunit` passes; new logic has a test (no internet needed, external services mocked)
- [ ] Outgoing requests use `SafeHttp` / the existing clients; all external data is treated as untrusted and escaped
- [ ] User-facing texts are German, code and documentation are English
- [ ] No secrets, no copied code or data from incompatible licenses
- [ ] Documentation updated (README, `docs/`, CHANGELOG entry)

## How was it tested?

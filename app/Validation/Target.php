<?php
declare(strict_types=1);

namespace DomainScope\Validation;

/**
 * Ergebnis der Eingabeanalyse: Domain, Subdomain, URL oder IP-Adresse.
 */
final class Target
{
    public function __construct(
        public readonly string $type,           // domain | ip | invalid
        public readonly string $input,
        public readonly ?string $host = null,   // ASCII-Hostname oder IP
        public readonly ?string $unicode = null,
        public readonly ?string $registrable = null,
        public readonly ?string $suffix = null,
        public readonly ?string $tld = null,
        public readonly bool $isSubdomain = false,
        public readonly bool $fromUrl = false,
        public readonly ?int $port = null,
        public readonly ?string $error = null,
    ) {
    }

    public function isDomain(): bool
    {
        return $this->type === 'domain';
    }

    public function isIp(): bool
    {
        return $this->type === 'ip';
    }

    public function valid(): bool
    {
        return $this->type !== 'invalid';
    }

    public static function parse(string $input): self
    {
        $raw = trim($input);
        if ($raw === '' || mb_strlen($raw) > 2048) {
            return new self('invalid', $raw, error: 'Eingabe ist leer oder zu lang.');
        }
        $fromUrl = false;
        $port = null;
        $host = $raw;

        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $raw)) {
            $scheme = strtolower((string) parse_url($raw, PHP_URL_SCHEME));
            if (!in_array($scheme, ['http', 'https'], true)) {
                return new self('invalid', $raw, error: 'Nur http- und https-URLs werden unterstützt.');
            }
            $parts = parse_url($raw);
            if ($parts === false || empty($parts['host'])) {
                // parse_url scheitert bei IDN-URLs teils; Host manuell extrahieren
                $host = (string) preg_replace('#^[a-z][a-z0-9+.-]*://([^/?\#]*).*$#iu', '$1', $raw);
                $host = (string) preg_replace('#^.*@#', '', $host);
                if (preg_match('/^(.*):(\d+)$/', $host, $m)) {
                    $host = $m[1];
                    $port = (int) $m[2];
                }
            } else {
                $host = $parts['host'];
                $port = $parts['port'] ?? null;
            }
            $fromUrl = true;
        } else {
            // "host/pfad", "host:port", "user@host" tolerieren
            $host = (string) preg_replace('#[/?\#].*$#u', '', $host);
            $host = (string) preg_replace('#^.*@#', '', $host);
            if (preg_match('/^\[(.+)\](?::(\d+))?$/', $host, $m)) {
                $host = $m[1];
                $port = isset($m[2]) && $m[2] !== '' ? (int) $m[2] : null;
            } elseif (substr_count($host, ':') === 1 && preg_match('/^(.*):(\d+)$/', $host, $m)) {
                $host = $m[1];
                $port = (int) $m[2];
            }
        }
        $host = trim($host, "[] \t");

        // IP-Adresse?
        if (IpClassifier::isValid($host)) {
            return new self('ip', $raw, host: IpClassifier::normalize($host), fromUrl: $fromUrl, port: $port);
        }
        // Dezimal-/Hex-/Oktal-IPv4-Tricks (2130706433, 0x7f.1) sind keine gültigen Domains
        if (preg_match('/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$/i', $host)) {
            return new self('invalid', $raw, error: 'Mehrdeutige numerische Adresse – bitte vollständige IPv4-Schreibweise a.b.c.d verwenden.');
        }

        $ascii = DomainName::normalize($host);
        if ($ascii === null) {
            return new self('invalid', $raw, error: 'Ungültiger Domainname.');
        }
        $suffix = PublicSuffix::suffix($ascii);
        $registrable = PublicSuffix::registrable($ascii);
        if ($registrable === null) {
            return new self(
                'domain', $raw, host: $ascii, unicode: DomainName::toUnicode($ascii), registrable: null,
                suffix: $suffix, tld: PublicSuffix::tld($ascii), isSubdomain: false, fromUrl: $fromUrl, port: $port,
                error: 'Die Eingabe ist ein Public Suffix und keine registrierbare Domain.'
            );
        }
        return new self(
            'domain', $raw, host: $ascii, unicode: DomainName::toUnicode($ascii), registrable: $registrable,
            suffix: $suffix, tld: PublicSuffix::tld($ascii), isSubdomain: $ascii !== $registrable,
            fromUrl: $fromUrl, port: $port
        );
    }
}

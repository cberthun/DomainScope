<?php
declare(strict_types=1);

namespace DomainScope\Services\RDAP;

use DomainScope\Services\Http\SafeHttp;
use DomainScope\Support\Config;
use DomainScope\Support\Logger;
use DomainScope\Validation\IpClassifier;

/**
 * Ermittelt RDAP-Endpunkte anhand der offiziellen IANA-Bootstrap-Dateien
 * (https://data.iana.org/rdap/). Lokale Kopien liegen in storage/data und werden bei Alter > 7 Tagen erneuert.
 */
final class RdapBootstrap
{
    private const MAX_AGE = 7 * 86400;
    private const BASE = 'https://data.iana.org/rdap/';

    /** @var array<string,array> */
    private static array $loaded = [];
    public static ?string $dataDir = null;
    public static bool $allowRefresh = true;

    /**
     * Ergänzung für TLDs, die einen RDAP-Dienst betreiben, aber nicht im IANA-Bootstrap stehen.
     * Der IANA-Eintrag hat immer Vorrang; diese Liste greift nur, wenn er fehlt.
     */
    private const SUPPLEMENTAL = ['de' => 'https://rdap.denic.de/'];

    public static function dnsService(string $tld): ?string
    {
        $tld = strtolower($tld);
        foreach (self::load('dns')['services'] ?? [] as [$tlds, $urls]) {
            if (in_array($tld, array_map('strtolower', $tlds), true)) {
                return self::pickUrl($urls);
            }
        }
        return self::SUPPLEMENTAL[$tld] ?? null;
    }

    public static function ipService(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        $file = strlen($bin) === 4 ? 'ipv4' : 'ipv6';
        $best = null;
        $bestBits = -1;
        foreach (self::load($file)['services'] ?? [] as [$cidrs, $urls]) {
            foreach ($cidrs as $cidr) {
                if (IpClassifier::inCidr($bin, $cidr)) {
                    $bits = (int) explode('/', $cidr)[1];
                    if ($bits > $bestBits) {
                        $bestBits = $bits;
                        $best = self::pickUrl($urls);
                    }
                }
            }
        }
        return $best;
    }

    public static function asnService(int $asn): ?string
    {
        foreach (self::load('asn')['services'] ?? [] as [$ranges, $urls]) {
            foreach ($ranges as $range) {
                [$lo, $hi] = array_map('intval', explode('-', $range . (str_contains($range, '-') ? '' : '-' . $range)));
                if ($asn >= $lo && $asn <= $hi) {
                    return self::pickUrl($urls);
                }
            }
        }
        return null;
    }

    /** @param string[] $urls */
    private static function pickUrl(array $urls): ?string
    {
        foreach ($urls as $u) {
            if (str_starts_with($u, 'https://')) {
                return rtrim($u, '/') . '/';
            }
        }
        return $urls ? rtrim($urls[0], '/') . '/' : null;
    }

    public static function load(string $name): array
    {
        if (isset(self::$loaded[$name])) {
            return self::$loaded[$name];
        }
        $dir = self::$dataDir ?? (string) Config::get('app.paths.data');
        $file = $dir . '/rdap-' . $name . '.json';
        $stale = !is_file($file) || (time() - (int) @filemtime($file)) > self::MAX_AGE;
        if ($stale && self::$allowRefresh) {
            self::refresh($name, $file);
        }
        $json = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
        return self::$loaded[$name] = is_array($json) ? $json : [];
    }

    public static function reset(): void
    {
        self::$loaded = [];
    }

    private static function refresh(string $name, string $file): void
    {
        $res = SafeHttp::request(self::BASE . $name . '.json', [
            'timeout' => 10, 'max_bytes' => 3_000_000, 'source' => 'iana-rdap-bootstrap', 'label' => 'IANA RDAP-Bootstrap',
        ]);
        if ($res['ok']) {
            $json = json_decode($res['body'], true);
            if (is_array($json) && isset($json['services'])) {
                @file_put_contents($file, $res['body'], LOCK_EX);
                return;
            }
        }
        // Veraltete Kopie behalten, aber Aktualisierung nicht bei jedem Aufruf neu versuchen
        if (is_file($file)) {
            @touch($file, time() - self::MAX_AGE + 3600);
        }
        Logger::warning('RDAP-Bootstrap konnte nicht aktualisiert werden: ' . $name);
    }
}

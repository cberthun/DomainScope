<?php
declare(strict_types=1);

namespace DomainScope\Services\Http;

use DomainScope\Services\DNS\DohClient;
use DomainScope\Validation\IpClassifier;

/**
 * Löst Hostnamen für aktive Verbindungen auf. Die Auflösung erfolgt über DoH (nicht über den lokalen Resolver),
 * damit interne Namen/Split-Horizon-Antworten nicht erreichbar sind. Die Ergebnisse werden anschließend an die
 * Verbindung gepinnt (kein erneutes Auflösen → Schutz vor DNS-Rebinding).
 */
final class HostResolver
{
    /** @var callable|null fn(string $host): string[] (Tests) */
    public static $override = null;
    /** @var array<string,string[]> */
    private static array $memo = [];
    private static ?DohClient $client = null;

    public static function useClient(?DohClient $c): void
    {
        self::$client = $c;
        self::$memo = [];
    }

    /** @return string[] alle A/AAAA-Adressen */
    public static function resolve(string $host): array
    {
        if (IpClassifier::isValid($host)) {
            return [IpClassifier::normalize($host) ?? $host];
        }
        if (self::$override !== null) {
            return (self::$override)($host);
        }
        $host = strtolower($host);
        if (isset(self::$memo[$host])) {
            return self::$memo[$host];
        }
        $client = self::$client ??= new DohClient();
        $reqs = [];
        foreach (['cloudflare', 'google'] as $resolver) {
            foreach (['A', 'AAAA'] as $type) {
                $reqs[] = ['resolver' => $resolver, 'name' => $host, 'type' => $type];
            }
        }
        $res = $client->queryMany(array_slice($reqs, 0, 2));
        $ips = self::collect($res);
        if ($ips === [] && !self::anyOk($res)) {
            $ips = self::collect($client->queryMany(array_slice($reqs, 2, 2)));
        }
        return self::$memo[$host] = $ips;
    }

    /** @param array<int,array> $results */
    private static function collect(array $results): array
    {
        $ips = [];
        foreach ($results as $r) {
            foreach ($r['answer'] as $rec) {
                if (in_array($rec['type'], ['A', 'AAAA'], true) && IpClassifier::isValid($rec['data'])) {
                    $ips[] = IpClassifier::normalize($rec['data']);
                }
            }
        }
        return array_values(array_unique(array_filter($ips)));
    }

    private static function anyOk(array $results): bool
    {
        foreach ($results as $r) {
            if (!in_array($r['status'], ['timeout', 'error'], true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Prüft, ob ein Ziel angesprochen werden darf, und liefert die zu verwendende IP.
     *
     * @return array{ok:bool,ip:?string,ips:string[],reason:?string}
     */
    public static function resolveSafe(string $host): array
    {
        $ips = self::resolve($host);
        if ($ips === []) {
            return ['ok' => false, 'ip' => null, 'ips' => [], 'reason' => 'Hostname ist nicht auflösbar (kein A/AAAA-Record).'];
        }
        foreach ($ips as $ip) {
            if (!IpClassifier::isPublic($ip)) {
                $label = IpClassifier::classify($ip)['label'];
                return ['ok' => false, 'ip' => null, 'ips' => $ips, 'reason' => "Verbindung blockiert: $host löst auf $ip auf ($label)."];
            }
        }
        // IPv4 bevorzugen (robuster erreichbar)
        usort($ips, static fn($a, $b) => (int) str_contains($a, ':') <=> (int) str_contains($b, ':'));
        return ['ok' => true, 'ip' => $ips[0], 'ips' => $ips, 'reason' => null];
    }
}

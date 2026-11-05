<?php
declare(strict_types=1);

namespace DomainScope\Services\IPIntelligence;

use DomainScope\Services\DNS\DohClient;
use DomainScope\Services\RDAP\RdapClient;
use DomainScope\Validation\IpClassifier;

/**
 * IP-Informationen: Klassifikation, Reverse-DNS, BGP-Origin-AS (Team Cymru per DNS), Registrierung (RDAP).
 * Registrierung (RIR), Routing (BGP) und ASN-Zuordnung sind getrennte Datenquellen. Eine Geolokalisierung
 * wird bewusst nicht geschätzt; angezeigt wird nur der in Registry-/BGP-Daten genannte Ländercode.
 */
final class IpIntelligenceService
{
    public function __construct(private readonly DohClient $doh, private readonly RdapClient $rdap = new RdapClient())
    {
    }

    /** @return array<string,mixed> */
    public function lookup(string $ip, bool $withRdap = true): array
    {
        $ip = IpClassifier::normalize($ip) ?? $ip;
        $cls = IpClassifier::classify($ip);
        $out = [
            'ip' => $ip, 'version' => IpClassifier::version($ip), 'classification' => $cls,
            'reverse_dns' => ['names' => [], 'status' => null, 'name' => IpClassifier::reverseName($ip)],
            'bgp' => null, 'asn_info' => null, 'registration' => null, 'checked_at' => gmdate('Y-m-d H:i:s'),
            'sources' => [],
        ];
        $reqs = [['resolver' => 'cloudflare', 'name' => (string) IpClassifier::reverseName($ip), 'type' => 'PTR']];
        if ($cls['public']) {
            $reqs[] = ['resolver' => 'cloudflare', 'name' => $this->cymruName($ip), 'type' => 'TXT'];
        }
        $res = $this->doh->queryMany($reqs);
        $ptr = $res[0];
        $out['reverse_dns']['status'] = $ptr['status'];
        foreach ($ptr['answer'] as $r) {
            if ($r['type'] === 'PTR') {
                $out['reverse_dns']['names'][] = $r['data'];
            }
        }
        $out['sources'][] = 'Reverse-DNS (PTR) über DNS-over-HTTPS';
        if (!$cls['public']) {
            return $out;
        }
        $origin = $res[1] ?? null;
        if ($origin && $origin['status'] === 'ok') {
            $line = $origin['answer'][0]['data'] ?? '';
            $parts = array_map('trim', explode('|', $line));
            if (count($parts) >= 3) {
                $asns = array_values(array_filter(array_map('intval', preg_split('/\s+/', $parts[0]) ?: [])));
                $out['bgp'] = [
                    'asns' => $asns, 'prefix' => $parts[1] ?: null, 'country' => $parts[2] ?: null,
                    'registry' => $parts[3] ?? null, 'allocated' => $parts[4] ?? null,
                ];
                $out['sources'][] = 'BGP-Origin: Team Cymru IP-to-ASN (DNS)';
            }
        }
        if ($out['bgp'] && $out['bgp']['asns']) {
            $asn = $out['bgp']['asns'][0];
            $name = $this->doh->query('cloudflare', "AS$asn.asn.cymru.com", 'TXT');
            if ($name['status'] === 'ok') {
                $p = array_map('trim', explode('|', $name['answer'][0]['data'] ?? ''));
                $out['asn_info'] = ['asn' => $asn, 'name' => $p[4] ?? null, 'country' => $p[1] ?? null, 'registry' => $p[2] ?? null, 'allocated' => $p[3] ?? null];
            }
        }
        if ($withRdap) {
            $r = $this->rdap->ip($ip);
            $out['registration'] = $r;
            if ($r['ok'] ?? false) {
                $out['sources'][] = 'IP-Registrierung: RDAP (' . ($r['source_url'] ?? '') . ')';
            }
        }
        return $out;
    }

    private function cymruName(string $ip): string
    {
        $bin = inet_pton($ip);
        if ($bin !== false && strlen($bin) === 4) {
            return implode('.', array_reverse(explode('.', $ip))) . '.origin.asn.cymru.com';
        }
        $hex = bin2hex((string) $bin);
        return implode('.', array_reverse(str_split($hex))) . '.origin6.asn.cymru.com';
    }
}

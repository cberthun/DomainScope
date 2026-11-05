<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

final class DnsTypes
{
    public const MAP = [
        'A' => 1, 'NS' => 2, 'CNAME' => 5, 'SOA' => 6, 'PTR' => 12, 'MX' => 15, 'TXT' => 16,
        'AAAA' => 28, 'SRV' => 33, 'NAPTR' => 35, 'DNAME' => 39, 'DS' => 43, 'RRSIG' => 46,
        'NSEC' => 47, 'DNSKEY' => 48, 'NSEC3' => 50, 'NSEC3PARAM' => 51, 'TLSA' => 52,
        'SVCB' => 64, 'HTTPS' => 65, 'CAA' => 257,
    ];

    /** Typen des DNS Explorers (Mindestumfang laut Anforderung). */
    public const EXPLORER = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'SRV', 'PTR', 'NAPTR', 'DS', 'DNSKEY'];

    public const RCODES = [
        0 => 'NOERROR', 1 => 'FORMERR', 2 => 'SERVFAIL', 3 => 'NXDOMAIN', 4 => 'NOTIMP', 5 => 'REFUSED',
    ];

    public static function name(int $code): string
    {
        $flip = array_flip(self::MAP);
        return $flip[$code] ?? ('TYPE' . $code);
    }

    public static function code(string $name): ?int
    {
        return self::MAP[strtoupper($name)] ?? null;
    }

    public static function rcodeName(int $rcode): string
    {
        return self::RCODES[$rcode] ?? ('RCODE' . $rcode);
    }
}

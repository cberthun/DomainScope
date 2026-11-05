<?php
declare(strict_types=1);

namespace DomainScope\Tests\Support;

use DomainScope\Services\DNS\{DnsLookup, DohClient};

/** Deterministischer DNS-over-HTTPS-Mock: Antworten werden pro (Name, Typ) vorgegeben. */
final class FakeDns
{
    private const TYPES = ['A' => 1, 'NS' => 2, 'CNAME' => 5, 'SOA' => 6, 'PTR' => 12, 'MX' => 15, 'TXT' => 16, 'AAAA' => 28, 'DS' => 43, 'RRSIG' => 46, 'DNSKEY' => 48, 'CAA' => 257, 'NSEC3PARAM' => 51, 'TLSA' => 52];

    /** @var array<string,array{rcode:int,answer:array,ad:bool,authority:array}> */
    public array $zone = [];
    /** @var string[] */
    public array $log = [];
    public ?string $failWith = null; // 'timeout' | 'error'

    /** @param array<int,array{0:string,1:string}> $records [[Typ, Daten], …] */
    public function set(string $name, string $type, array $records, int $rcode = 0, bool $ad = false): self
    {
        $answer = [];
        foreach ($records as $r) {
            $answer[] = ['name' => $name . '.', 'type' => self::TYPES[$r[0]], 'TTL' => 300, 'data' => $r[1]];
        }
        $this->zone[strtolower($name) . '|' . strtoupper($type)] = ['rcode' => $rcode, 'answer' => $answer, 'ad' => $ad, 'authority' => []];
        return $this;
    }

    public function txt(string $name, string ...$values): self
    {
        return $this->set($name, 'TXT', array_map(static fn($v) => ['TXT', '"' . $v . '"'], $values));
    }

    public function client(): DohClient
    {
        return new DohClient(function (string $url, array $headers): array {
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            $name = strtolower((string) ($q['name'] ?? ''));
            $type = strtoupper((string) ($q['type'] ?? ''));
            $this->log[] = "$name|$type";
            if ($this->failWith === 'timeout') {
                return ['body' => null, 'http' => 0, 'error' => 'Operation timed out', 'errno' => CURLE_OPERATION_TIMEOUTED, 'ms' => 6000];
            }
            if ($this->failWith === 'error') {
                return ['body' => null, 'http' => 0, 'error' => 'Could not resolve host', 'errno' => 6, 'ms' => 5];
            }
            $entry = $this->zone["$name|$type"] ?? ['rcode' => 0, 'answer' => [], 'ad' => false, 'authority' => []];
            $body = ['Status' => $entry['rcode'], 'TC' => false, 'RD' => true, 'RA' => true, 'AD' => $entry['ad'], 'CD' => false,
                'Question' => [['name' => $name . '.', 'type' => self::TYPES[$type] ?? 1]]];
            if ($entry['answer']) {
                $body['Answer'] = $entry['answer'];
            }
            return ['body' => json_encode($body), 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 12];
        });
    }

    public function lookup(int $budget = 80): DnsLookup
    {
        return new DnsLookup($this->client(), 'cloudflare', $budget);
    }
}

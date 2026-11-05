<?php
declare(strict_types=1);

namespace DomainScope\Services\Subdomains;

use DomainScope\Services\DNS\DohClient;
use DomainScope\Services\Http\SafeHttp;
use DomainScope\Validation\DomainName;

/**
 * Passive Subdomain-Erkennung über Certificate-Transparency-Quellen (crt.sh, Cert Spotter).
 * Es werden keinerlei aktive Verbindungen zur Zieldomain aufgebaut. Ein passiver Fund beweist nicht,
 * dass der Host aktuell existiert oder erreichbar ist.
 */
final class SubdomainDiscovery
{
    /**
     * @return array{hosts:array<string,array>,wildcards:string[],sources:array<string,array>,errors:array<string,string>}
     */
    public function discover(string $domain): array
    {
        $hosts = [];
        $wild = [];
        $sources = [];
        $errors = [];

        foreach (['crtsh' => 'fetchCrtSh', 'certspotter' => 'fetchCertSpotter'] as $name => $method) {
            $res = $this->$method($domain);
            if ($res['error'] !== null) {
                $errors[$name] = $res['error'];
                continue;
            }
            $sources[$name] = ['entries' => $res['entries'], 'ms' => $res['ms']];
            foreach ($res['names'] as $raw => $meta) {
                $this->collect($domain, (string) $raw, $name, $meta, $hosts, $wild);
            }
        }
        ksort($hosts);
        return ['hosts' => $hosts, 'wildcards' => array_values(array_unique($wild)), 'sources' => $sources, 'errors' => $errors, 'certs' => isset($sources['crtsh']) ? array_values($this->certs) : null];
    }

    /**
     * @param array<string,array> $hosts
     * @param string[] $wild
     */
    private function collect(string $domain, string $raw, string $source, array $meta, array &$hosts, array &$wild): void
    {
        $name = strtolower(trim($raw));
        if ($name === '' || str_contains($name, '@') || str_contains($name, ' ')) {
            return;
        }
        $isWild = false;
        if (str_starts_with($name, '*.')) {
            $isWild = true;
            $name = substr($name, 2);
        }
        $ascii = DomainName::normalize($name, true);
        if ($ascii === null || ($ascii !== $domain && !str_ends_with($ascii, '.' . $domain))) {
            return;
        }
        if ($isWild) {
            $wild[] = '*.' . $ascii;
            return;
        }
        $h = &$hosts[$ascii];
        $h ??= ['sources' => [], 'not_after' => null, 'not_before' => null, 'issuers' => []];
        $h['sources'][$source] = true;
        if (!empty($meta['not_after']) && ($h['not_after'] === null || $meta['not_after'] > $h['not_after'])) {
            $h['not_after'] = $meta['not_after'];
        }
        if (!empty($meta['not_before']) && ($h['not_before'] === null || $meta['not_before'] < $h['not_before'])) {
            $h['not_before'] = $meta['not_before'];
        }
        if (!empty($meta['issuer'])) {
            $h['issuers'][$meta['issuer']] = true;
        }
    }

    /** @var array<string,array> Zertifikate aus crt.sh (Schlüssel: Seriennummer|Aussteller) */
    private array $certs = [];

    private function collectCert(string $domain, array $e): void
    {
        $serial = strtolower(ltrim((string) ($e['serial_number'] ?? ''), '0'));
        $issuer = mb_substr((string) preg_replace('/^.*?CN=/', '', (string) ($e['issuer_name'] ?? '')), 0, 190);
        if ($serial === '' || $issuer === '') {
            return;
        }
        $names = [];
        foreach (preg_split('/\R/', (string) $e['name_value']) ?: [] as $n) {
            $n = strtolower(trim($n));
            $bare = ltrim($n, '*.');
            if ($bare === $domain || str_ends_with($bare, '.' . $domain)) {
                $names[] = $n;
            }
        }
        if ($names === []) {
            return;
        }
        $k = $serial . '|' . $issuer;
        $this->certs[$k] ??= ['serial' => $serial, 'issuer' => $issuer, 'ct_id' => (string) ($e['id'] ?? ''), 'names' => [], 'not_before' => self::date($e['not_before'] ?? null), 'not_after' => self::date($e['not_after'] ?? null)];
        $this->certs[$k]['names'] = array_values(array_unique(array_merge($this->certs[$k]['names'], $names)));
    }

    /** @return array{names:array<string,array>,entries:int,ms:int,error:?string} */
    private function fetchCrtSh(string $domain): array
    {
        $url = 'https://crt.sh/?q=' . rawurlencode('%.' . $domain) . '&output=json';
        $r = SafeHttp::request($url, ['max_bytes' => 12_000_000, 'timeout' => 40, 'source' => 'crtsh', 'label' => 'Certificate Transparency: crt.sh']);
        $this->certs = [];
        return $this->parse($r, function (array $json) use ($domain): array {
            $names = [];
            foreach ($json as $e) {
                if (!is_array($e) || !isset($e['name_value'])) {
                    continue;
                }
                $this->collectCert($domain, $e);
                foreach (preg_split('/\R/', (string) $e['name_value']) ?: [] as $n) {
                    $names[$n] = [
                        'not_after' => self::date($e['not_after'] ?? null), 'not_before' => self::date($e['not_before'] ?? null),
                        'issuer' => isset($e['issuer_name']) ? mb_substr((string) preg_replace('/^.*?CN=/', '', (string) $e['issuer_name']), 0, 120) : null,
                    ];
                }
            }
            return [$names, count($json)];
        });
    }

    /** @return array{names:array<string,array>,entries:int,ms:int,error:?string} */
    private function fetchCertSpotter(string $domain): array
    {
        $url = 'https://api.certspotter.com/v1/issuances?domain=' . rawurlencode($domain) . '&include_subdomains=true&expand=dns_names';
        $r = SafeHttp::request($url, ['max_bytes' => 6_000_000, 'timeout' => 25, 'source' => 'certspotter', 'label' => 'Certificate Transparency: Cert Spotter']);
        if ($r['status'] === 429) {
            return ['names' => [], 'entries' => 0, 'ms' => $r['ms'], 'error' => 'Rate-Limit (HTTP 429) – anonyme Anfragen sind stark begrenzt.'];
        }
        return $this->parse($r, static function (array $json): array {
            $names = [];
            foreach ($json as $e) {
                if (!is_array($e)) {
                    continue;
                }
                foreach ((array) ($e['dns_names'] ?? []) as $n) {
                    $names[(string) $n] = ['not_after' => self::date($e['not_after'] ?? null), 'not_before' => self::date($e['not_before'] ?? null), 'issuer' => null];
                }
            }
            return [$names, count($json)];
        });
    }

    /** @return array{names:array<string,array>,entries:int,ms:int,error:?string} */
    private function parse(array $r, callable $extract): array
    {
        $fail = static fn(string $m) => ['names' => [], 'entries' => 0, 'ms' => $r['ms'], 'error' => $m];
        if ($r['error_code'] !== null) {
            return $fail($r['error_code'] === 'timeout' ? 'Zeitüberschreitung der Datenquelle.' : (string) $r['error']);
        }
        if ($r['status'] !== 200) {
            return $fail('HTTP ' . $r['status'] . ' von der Datenquelle.');
        }
        if ($r['truncated']) {
            return $fail('Antwort überschreitet das Größenlimit (zu viele Zertifikate).');
        }
        $json = json_decode($r['body'], true);
        if (!is_array($json)) {
            return $fail('Antwort ist kein gültiges JSON (Quelle überlastet?).');
        }
        [$names, $count] = $extract($json);
        return ['names' => $names, 'entries' => $count, 'ms' => $r['ms'], 'error' => null];
    }

    private static function date(mixed $v): ?string
    {
        if (!is_string($v) || $v === '') {
            return null;
        }
        try {
            return (new \DateTimeImmutable($v, new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Optionale DNS-Auflösung gefundener Hosts (begrenzt).
     *
     * @param string[] $hostnames
     * @return array<string,array{status:string,ips:string[],cname:?string}>
     */
    public function resolve(DohClient $doh, array $hostnames, int $limit, string $resolver = 'cloudflare'): array
    {
        $hostnames = array_slice($hostnames, 0, max(0, $limit));
        $reqs = [];
        foreach ($hostnames as $h) {
            $reqs[] = ['resolver' => $resolver, 'name' => $h, 'type' => 'A'];
            $reqs[] = ['resolver' => $resolver, 'name' => $h, 'type' => 'AAAA'];
        }
        $res = $doh->queryMany($reqs);
        $out = [];
        foreach ($hostnames as $i => $h) {
            $a = $res[$i * 2];
            $aaaa = $res[$i * 2 + 1];
            $ips = [];
            $cname = null;
            foreach ([$a, $aaaa] as $r) {
                foreach ($r['answer'] as $rec) {
                    if (in_array($rec['type'], ['A', 'AAAA'], true)) {
                        $ips[] = $rec['data'];
                    } elseif ($rec['type'] === 'CNAME' && $cname === null) {
                        $cname = $rec['data'];
                    }
                }
            }
            $status = match (true) {
                $ips !== [] => 'resolves',
                $a['status'] === 'nxdomain' => 'nxdomain',
                in_array($a['status'], ['timeout', 'error', 'servfail'], true) => 'error',
                $cname !== null => 'dangling_cname',
                default => 'nodata',
            };
            $out[$h] = ['status' => $status, 'ips' => array_values(array_unique($ips)), 'cname' => $cname];
        }
        return $out;
    }
}

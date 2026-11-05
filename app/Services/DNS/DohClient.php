<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

use DomainScope\Services\Http\CurlSupport;
use DomainScope\Support\Cache;
use DomainScope\Support\Config;
use DomainScope\Support\DataSources;
use DomainScope\Support\Settings;

/**
 * DNS-over-HTTPS-Client (JSON-API von Cloudflare, Google, Quad9).
 *
 * Alle Ergebnisse sind normalisierte Arrays:
 *  status: ok | nodata | nxdomain | servfail | refused | formerr | timeout | error
 */
final class DohClient
{
    /** @var callable|null fn(string $url, array $headers): array{body:?string,http:int,error:?string,ms:int} */
    private $transport;
    /** @var array<string,array> */
    private array $memo = [];

    public function __construct(?callable $transport = null)
    {
        $this->transport = $transport;
    }

    /**
     * @param array{do?:bool,cd?:bool,fresh?:bool} $opts
     */
    public function query(string $resolver, string $name, string $type, array $opts = []): array
    {
        return $this->queryMany([['resolver' => $resolver, 'name' => $name, 'type' => $type, 'opts' => $opts]])[0];
    }

    /**
     * Führt mehrere Abfragen mit begrenzter Parallelität aus; Reihenfolge der Ergebnisse = Reihenfolge der Anfragen.
     *
     * @param array<int,array{resolver:string,name:string,type:string,opts?:array}> $requests
     * @return array<int,array>
     */
    public function queryMany(array $requests): array
    {
        $results = [];
        $pending = [];
        $ttl = max(0, Settings::int('cache_ttl'));
        foreach ($requests as $i => $r) {
            $opts = $r['opts'] ?? [];
            $key = $this->cacheKey($r['resolver'], $r['name'], $r['type'], $opts);
            if (isset($this->memo[$key])) {
                $results[$i] = $this->memo[$key];
                continue;
            }
            if ($ttl > 0 && empty($opts['fresh']) && $this->transport === null) {
                $cached = Cache::get('doh:' . $key);
                if (is_array($cached)) {
                    $cached['cached'] = true;
                    $this->memo[$key] = $results[$i] = $cached;
                    continue;
                }
            }
            $pending[$i] = $r + ['key' => $key];
        }
        $max = max(1, (int) Config::get('app.dns.max_parallel', 6));
        foreach (array_chunk($pending, $max, true) as $chunk) {
            foreach ($this->fetchChunk($chunk) as $i => $res) {
                $results[$i] = $res;
                $key = $pending[$i]['key'];
                $this->memo[$key] = $res;
                if ($ttl > 0 && !in_array($res['status'], ['timeout', 'error'], true) && $this->transport === null) {
                    Cache::set('doh:' . $key, $res, $ttl);
                }
            }
        }
        ksort($results);
        return array_values($results);
    }

    private function cacheKey(string $resolver, string $name, string $type, array $opts): string
    {
        return implode('|', [$resolver, strtolower($name), strtoupper($type), (int) !empty($opts['do']), (int) !empty($opts['cd'])]);
    }

    /**
     * @param array<int,array> $chunk
     * @return array<int,array>
     */
    private function fetchChunk(array $chunk): array
    {
        $out = [];
        $prepared = [];
        foreach ($chunk as $i => $r) {
            $resolvers = (array) Config::get('app.dns.resolvers');
            if (!isset($resolvers[$r['resolver']])) {
                $out[$i] = $this->errorResult($r, 'error', 'Unbekannter Resolver: ' . $r['resolver']);
                continue;
            }
            $opts = $r['opts'] ?? [];
            $query = ['name' => $r['name'], 'type' => strtoupper($r['type'])];
            if (!empty($opts['do'])) {
                $query['do'] = '1';
            }
            if (!empty($opts['cd'])) {
                $query['cd'] = '1';
            }
            $prepared[$i] = [
                'url' => $resolvers[$r['resolver']]['url'] . '?' . http_build_query($query),
                'req' => $r,
            ];
        }

        if ($this->transport !== null) {
            foreach ($prepared as $i => $p) {
                $raw = ($this->transport)($p['url'], ['Accept: application/dns-json']);
                $out[$i] = $this->interpret($p['req'], $raw);
            }
            return $out;
        }

        $timeout = (int) Config::get('app.dns.timeout', 6);
        $mh = curl_multi_init();
        $handles = [];
        $bodies = [];
        foreach ($prepared as $i => $p) {
            $ch = curl_init($p['url']);
            $bodies[$i] = '';
            curl_setopt_array($ch, CurlSupport::baseOptions($timeout, 4) + [
                CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
                CURLOPT_RETURNTRANSFER => false,
                CURLOPT_WRITEFUNCTION => static function ($c, string $data) use (&$bodies, $i): int {
                    $bodies[$i] .= $data;
                    return strlen($bodies[$i]) > 1_000_000 ? 0 : strlen($data);
                },
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$i] = $ch;
        }
        $running = 0;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running > 0) {
                curl_multi_select($mh, 0.5);
            }
        } while ($running > 0 && $status === CURLM_OK);

        foreach ($handles as $i => $ch) {
            $err = curl_error($ch);
            $errno = curl_errno($ch);
            $raw = [
                'body' => $bodies[$i] !== '' ? $bodies[$i] : null,
                'http' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
                'error' => $errno !== 0 ? $err : null,
                'errno' => $errno,
                'ms' => (int) round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000),
            ];
            curl_multi_remove_handle($mh, $ch);
            $out[$i] = $this->interpret($prepared[$i]['req'], $raw);
        }
        curl_multi_close($mh);
        return $out;
    }

    /** @param array{body:?string,http:int,error:?string,ms:int,errno?:int} $raw */
    private function interpret(array $r, array $raw): array
    {
        $resolver = $r['resolver'];
        $source = 'doh:' . $resolver;
        if ($raw['error'] !== null || $raw['body'] === null || $raw['http'] !== 200) {
            $timedOut = ($raw['errno'] ?? 0) === CURLE_OPERATION_TIMEOUTED || str_contains((string) $raw['error'], 'timed out');
            $msg = $raw['error'] ?? ('HTTP ' . $raw['http']);
            DataSources::fail($source, $this->label($resolver), $msg, (int) $raw['ms']);
            return $this->errorResult($r, $timedOut ? 'timeout' : 'error', $msg, (int) $raw['ms']);
        }
        $json = json_decode($raw['body'], true);
        if (!is_array($json) || !isset($json['Status'])) {
            DataSources::fail($source, $this->label($resolver), 'Ungültige Antwort', (int) $raw['ms']);
            return $this->errorResult($r, 'error', 'Ungültige Resolver-Antwort (kein DNS-JSON).', (int) $raw['ms']);
        }
        DataSources::ok($source, $this->label($resolver), (int) $raw['ms']);

        $rcode = (int) $json['Status'];
        $answer = $this->records($json['Answer'] ?? []);
        $authority = $this->records($json['Authority'] ?? []);
        $additional = $this->records($json['Additional'] ?? []);
        $wanted = DnsTypes::code($r['type']);
        $matching = array_values(array_filter($answer, static fn($rec) => $wanted === null || $rec['type_code'] === $wanted));

        $status = match ($rcode) {
            0 => $matching === [] && $answer === [] ? 'nodata' : 'ok',
            1 => 'formerr',
            2 => 'servfail',
            3 => 'nxdomain',
            5 => 'refused',
            default => 'error',
        };
        // Antwort nur mit CNAME-Kette aber ohne Zieltyp = ebenfalls "nodata" für den Zieltyp
        if ($status === 'ok' && $matching === [] && $r['type'] !== 'CNAME') {
            $status = 'nodata';
        }
        return [
            'resolver' => $resolver,
            'name' => $r['name'],
            'type' => strtoupper($r['type']),
            'rcode' => $rcode,
            'rcode_name' => DnsTypes::rcodeName($rcode),
            'status' => $status,
            'flags' => [
                'AD' => (bool) ($json['AD'] ?? false), 'CD' => (bool) ($json['CD'] ?? false),
                'RA' => (bool) ($json['RA'] ?? false), 'RD' => (bool) ($json['RD'] ?? false),
                'TC' => (bool) ($json['TC'] ?? false),
            ],
            'answer' => $answer,
            'authority' => $authority,
            'additional' => $additional,
            'ms' => (int) $raw['ms'],
            'error' => null,
            'explanation' => self::explain($status, $r['name'], strtoupper($r['type'])),
            'extended_errors' => $json['Comment'] ?? null,
            'raw' => $json,
            'cached' => false,
        ];
    }

    private function errorResult(array $r, string $status, string $message, int $ms = 0): array
    {
        return [
            'resolver' => $r['resolver'], 'name' => $r['name'], 'type' => strtoupper($r['type']),
            'rcode' => null, 'rcode_name' => null, 'status' => $status,
            'flags' => ['AD' => false, 'CD' => false, 'RA' => false, 'RD' => false, 'TC' => false],
            'answer' => [], 'authority' => [], 'additional' => [], 'ms' => $ms,
            'error' => $message, 'explanation' => self::explain($status, $r['name'], strtoupper($r['type'])),
            'extended_errors' => null, 'raw' => null, 'cached' => false,
        ];
    }

    private function label(string $resolver): string
    {
        return 'DNS-over-HTTPS: ' . ((string) Config::get("app.dns.resolvers.$resolver.label", $resolver));
    }

    /** @return array<int,array{name:string,type:string,type_code:int,ttl:int,data:string}> */
    private function records(array $rows): array
    {
        $out = [];
        foreach ($rows as $row) {
            if (!is_array($row) || !isset($row['type'], $row['data'])) {
                continue;
            }
            $code = (int) $row['type'];
            $type = DnsTypes::name($code);
            $out[] = [
                'name' => rtrim(strtolower((string) ($row['name'] ?? '')), '.'),
                'type' => $type,
                'type_code' => $code,
                'ttl' => (int) ($row['TTL'] ?? 0),
                'data' => RecordFormatter::normalize($type, (string) $row['data']),
            ];
        }
        return $out;
    }

    public static function explain(string $status, string $name, string $type): string
    {
        return match ($status) {
            'ok' => 'Die Abfrage war erfolgreich.',
            'nodata' => "Der Name $name existiert, aber es gibt keine Records vom Typ $type (NOERROR/NODATA).",
            'nxdomain' => "Der Name $name existiert nicht (NXDOMAIN). Entweder nicht registriert oder die Subdomain ist nicht angelegt.",
            'servfail' => 'Der Resolver konnte keine verwertbare Antwort liefern (SERVFAIL). Häufige Ursachen: nicht erreichbare oder fehlerhafte autoritative Nameserver, fehlerhafte DNSSEC-Signaturen/DS-Records.',
            'refused' => 'Die Anfrage wurde abgelehnt (REFUSED). Der Server beantwortet diese Abfrage nicht (Richtlinie/ACL).',
            'formerr' => 'Der Server hat die Anfrage als fehlerhaft formatiert zurückgewiesen (FORMERR).',
            'timeout' => 'Zeitüberschreitung: Der Resolver hat nicht rechtzeitig geantwortet. Das ist kein DNS-Befund über die Domain.',
            default => 'Die Abfrage ist fehlgeschlagen (Netzwerk- oder Resolver-Fehler). Es liegt keine DNS-Aussage vor.',
        };
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Services\WHOIS;

use DomainScope\Services\Http\HostResolver;
use DomainScope\Support\DataSources;
use DomainScope\Validation\DomainName;

/**
 * Kontrollierter WHOIS-Fallback (Port 43) für TLDs ohne RDAP. Server werden über whois.iana.org ermittelt;
 * Verbindungen gehen ausschließlich zu öffentlichen IPs und sind in Zeit und Größe begrenzt.
 */
final class WhoisClient
{
    private const MAX_BYTES = 100_000;
    /** @var callable|null fn(string $server, string $query): ?string (Tests) */
    public static $transport = null;

    /** @return array<string,mixed> */
    public function domain(string $domain): array
    {
        $tld = substr($domain, (int) strrpos($domain, '.') + 1);
        $iana = $this->query('whois.iana.org', $tld);
        if ($iana === null) {
            return $this->fail('unreachable', 'whois.iana.org ist nicht erreichbar.');
        }
        if (!preg_match('/^whois:\s*(\S+)/mi', $iana, $m)) {
            return $this->fail('unsupported_tld', "Für .$tld ist kein WHOIS-Server bekannt.");
        }
        $server = strtolower($m[1]);
        if (DomainName::normalize($server) === null) {
            return $this->fail('invalid_response', 'Ungültiger WHOIS-Servername in der IANA-Antwort.');
        }
        $query = $server === 'whois.denic.de' ? '-T dn,ace ' . $domain : $domain;
        $raw = $this->query($server, $query);
        if ($raw === null) {
            return $this->fail('unreachable', "WHOIS-Server $server nicht erreichbar.");
        }
        return $this->parse($raw, $server);
    }

    /** @return array<string,mixed> */
    public function parse(string $raw, string $server): array
    {
        $raw = preg_replace('/[^\P{C}\n\t]+/u', '', mb_convert_encoding($raw, 'UTF-8', 'UTF-8,ISO-8859-1')) ?? '';
        $fields = [];
        foreach (preg_split('/\R/', $raw) ?: [] as $line) {
            if (preg_match('/^\s*([A-Za-z][A-Za-z0-9 \/_-]{1,40}):\s*(.+?)\s*$/', $line, $m)) {
                $fields[strtolower(trim($m[1]))][] = $m[2];
            }
        }
        if (preg_match('/^\s*(no match|not found|no entries found|status:\s*free|domain not found)/mi', $raw) && !isset($fields['registrar'])) {
            return $this->fail('not_found', 'WHOIS meldet: Domain nicht gefunden oder frei.') + ['raw' => mb_substr($raw, 0, 4000)];
        }
        $first = static function (array $keys) use ($fields): ?string {
            foreach ($keys as $k) {
                if (!empty($fields[$k][0])) {
                    return $fields[$k][0];
                }
            }
            return null;
        };
        $date = static function (?string $v): ?string {
            if ($v === null) {
                return null;
            }
            try {
                return (new \DateTimeImmutable($v, new \DateTimeZone('UTC')))->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
            } catch (\Throwable) {
                return null;
            }
        };
        $ns = [];
        foreach (['name server', 'nserver', 'nameserver', 'nameservers'] as $k) {
            foreach ($fields[$k] ?? [] as $v) {
                $host = strtolower(trim(explode(' ', $v)[0], '. '));
                if ($host !== '') {
                    $ns[] = $host;
                }
            }
        }
        $ns = array_values(array_unique($ns));
        sort($ns);
        $statuses = array_values(array_unique(array_map(static fn($s) => trim(explode(' ', $s)[0]), $fields['domain status'] ?? ($fields['status'] ?? []))));
        return [
            'ok' => true, 'source' => 'whois', 'source_url' => 'whois://' . $server,
            'registrar' => $first(['registrar', 'sponsoring registrar', 'registrar name']),
            'registered_at' => $date($first(['creation date', 'created', 'registered', 'registration time'])),
            'changed_at' => $date($first(['updated date', 'last updated', 'changed', 'last-update', 'last modified'])),
            'expires_at' => $date($first(['registry expiry date', 'registrar registration expiration date', 'expiry date', 'expires', 'paid-till', 'expire date'])),
            'statuses' => $statuses, 'nameservers' => $ns,
            'dnssec_signed' => isset($fields['dnssec']) ? (bool) preg_match('/^(signed|yes)/i', $fields['dnssec'][0]) : null,
            'entities' => [], 'events' => [], 'notes' => ['WHOIS-Rohtext ist unstrukturiert; Felder werden heuristisch ausgewertet.'],
            'raw' => mb_substr($raw, 0, 8000), 'fetched_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    private function fail(string $code, string $msg): array
    {
        return ['ok' => false, 'source' => 'whois', 'error_code' => $code, 'error' => $msg, 'fetched_at' => gmdate('Y-m-d H:i:s')];
    }

    private function query(string $server, string $query): ?string
    {
        if (self::$transport !== null) {
            return (self::$transport)($server, $query);
        }
        $safe = HostResolver::resolveSafe($server);
        if (!$safe['ok']) {
            DataSources::fail('whois:' . $server, 'WHOIS ' . $server, (string) $safe['reason']);
            return null;
        }
        $started = microtime(true);
        $ip = str_contains((string) $safe['ip'], ':') ? '[' . $safe['ip'] . ']' : $safe['ip'];
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client("tcp://$ip:43", $errno, $errstr, 6);
        if (!$fp) {
            DataSources::fail('whois:' . $server, 'WHOIS ' . $server, "$errstr ($errno)");
            return null;
        }
        stream_set_timeout($fp, 8);
        fwrite($fp, $query . "\r\n");
        $out = '';
        while (!feof($fp) && strlen($out) < self::MAX_BYTES) {
            $chunk = fread($fp, 4096);
            if ($chunk === false || $chunk === '') {
                if (stream_get_meta_data($fp)['timed_out']) {
                    break;
                }
                continue;
            }
            $out .= $chunk;
        }
        fclose($fp);
        DataSources::ok('whois:' . $server, 'WHOIS ' . $server, (int) round((microtime(true) - $started) * 1000));
        return $out;
    }
}

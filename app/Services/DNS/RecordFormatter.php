<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

/** Normalisierung und Parsing von DNS-Record-Daten (nicht vertrauenswürdige Eingaben). */
final class RecordFormatter
{
    public static function normalize(string $type, string $data): string
    {
        $data = trim($data);
        return match ($type) {
            'TXT' => self::txt($data),
            'CNAME', 'NS', 'PTR', 'DNAME' => self::name($data),
            'MX' => self::mx($data),
            'SOA' => self::soa($data),
            'SRV' => self::srv($data),
            'DNSKEY' => self::collapse($data),
            'A' => $data,
            'AAAA' => (inet_ntop((string) @inet_pton($data)) ?: $data),
            default => self::collapse($data),
        };
    }

    public static function name(string $s): string
    {
        return rtrim(strtolower(trim($s)), '.');
    }

    private static function collapse(string $s): string
    {
        return trim(preg_replace('/\s+/', ' ', $s) ?? $s);
    }

    /** TXT-Daten: Anführungszeichen und Segmentierung entfernen, Segmente zusammenfügen. */
    public static function txt(string $data): string
    {
        $data = trim($data);
        if ($data !== '' && $data[0] === '"') {
            if (preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/s', $data, $m) && $m[0] !== []) {
                return implode('', array_map(static fn($seg) => stripcslashes($seg), $m[1]));
            }
        }
        return $data;
    }

    private static function mx(string $s): string
    {
        $p = preg_split('/\s+/', $s, 2) ?: [];
        return count($p) === 2 ? ((int) $p[0]) . ' ' . (self::name($p[1]) ?: '.') : $s;
    }

    private static function soa(string $s): string
    {
        $p = preg_split('/\s+/', $s) ?: [];
        if (count($p) >= 7) {
            $p[0] = self::name($p[0]);
            $p[1] = self::name($p[1]);
            return implode(' ', $p);
        }
        return $s;
    }

    private static function srv(string $s): string
    {
        $p = preg_split('/\s+/', $s) ?: [];
        if (count($p) === 4) {
            $p[3] = self::name($p[3]) ?: '.';
            return implode(' ', $p);
        }
        return $s;
    }

    /** @return array{priority:int,host:string}|null */
    public static function parseMx(string $data): ?array
    {
        if (!preg_match('/^(\d+)\s+(\S+)$/', trim($data), $m)) {
            return null;
        }
        return ['priority' => (int) $m[1], 'host' => rtrim(strtolower($m[2]), '.')];
    }

    /** @return array<string,string|int>|null */
    public static function parseSoa(string $data): ?array
    {
        $p = preg_split('/\s+/', trim($data)) ?: [];
        if (count($p) < 7) {
            return null;
        }
        return [
            'mname' => rtrim($p[0], '.'), 'rname' => rtrim($p[1], '.'), 'serial' => (int) $p[2],
            'refresh' => (int) $p[3], 'retry' => (int) $p[4], 'expire' => (int) $p[5], 'minimum' => (int) $p[6],
        ];
    }

    /** @return array{flags:int,tag:string,value:string}|null */
    public static function parseCaa(string $data): ?array
    {
        // Cloudflare liefert "0 issue \"letsencrypt.org\"", Google evtl. hex "\# 22 ..."
        if (str_starts_with($data, '\\#')) {
            $p = preg_split('/\s+/', $data) ?: [];
            $hex = implode('', array_slice($p, 2));
            $bin = @hex2bin($hex);
            if ($bin === false || strlen($bin) < 2) {
                return null;
            }
            $flags = ord($bin[0]);
            $tagLen = ord($bin[1]);
            return ['flags' => $flags, 'tag' => substr($bin, 2, $tagLen), 'value' => substr($bin, 2 + $tagLen)];
        }
        if (!preg_match('/^(\d+)\s+([A-Za-z0-9]+)\s+(.*)$/s', trim($data), $m)) {
            return null;
        }
        return ['flags' => (int) $m[1], 'tag' => strtolower($m[2]), 'value' => trim($m[3], '"')];
    }

    /** @return array{keytag:int,algorithm:int,digest_type:int,digest:string}|null */
    public static function parseDs(string $data): ?array
    {
        if (!preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f\s]+)$/', trim($data), $m)) {
            return null;
        }
        return ['keytag' => (int) $m[1], 'algorithm' => (int) $m[2], 'digest_type' => (int) $m[3], 'digest' => strtolower(preg_replace('/\s+/', '', $m[4]) ?? '')];
    }

    /** @return array{flags:int,protocol:int,algorithm:int,key:string}|null */
    public static function parseDnskey(string $data): ?array
    {
        if (!preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/s', trim($data), $m)) {
            return null;
        }
        return ['flags' => (int) $m[1], 'protocol' => (int) $m[2], 'algorithm' => (int) $m[3], 'key' => preg_replace('/\s+/', '', $m[4]) ?? ''];
    }

    /** @return array<string,mixed>|null */
    public static function parseRrsig(string $data): ?array
    {
        $p = preg_split('/\s+/', trim($data)) ?: [];
        if (count($p) < 9) {
            return null;
        }
        return [
            'covered' => strtoupper($p[0]), 'algorithm' => (int) $p[1], 'labels' => (int) $p[2], 'original_ttl' => (int) $p[3],
            'expiration' => self::sigTime($p[4]), 'inception' => self::sigTime($p[5]),
            'keytag' => (int) $p[6], 'signer' => rtrim(strtolower($p[7]), '.'), 'signature' => implode('', array_slice($p, 8)),
        ];
    }

    private static function sigTime(string $s): ?int
    {
        if (preg_match('/^\d{14}$/', $s)) {
            $d = \DateTimeImmutable::createFromFormat('YmdHis', $s, new \DateTimeZone('UTC'));
            return $d ? $d->getTimestamp() : null;
        }
        return ctype_digit($s) ? (int) $s : null;
    }

    /** Sortierschlüssel-stabile Darstellung eines Record-Sets für Hashes/Diffs. */
    public static function canonicalKey(array $rec): string
    {
        return strtolower($rec['name']) . "\t" . $rec['type'] . "\t" . $rec['data'];
    }
}

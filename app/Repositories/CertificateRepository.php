<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class CertificateRepository
{
    /**
     * Speichert Zertifikat und Prüfung.
     *
     * @param array<string,mixed> $r Ergebnis von TlsInspector::inspect()
     * @return array{check_id:int,certificate_id:?int,new_certificate:bool,previous_fingerprint:?string}
     */
    public static function save(int $domainId, array $r): array
    {
        $prev = self::latestCheck($domainId, $r['host'], (int) $r['port']);
        $certId = null;
        $new = false;
        if (!empty($r['certificate'])) {
            $c = $r['certificate'];
            $existing = Database::one('SELECT id FROM certificates WHERE fingerprint_sha256 = ?', [$c['fingerprint_sha256']]);
            if ($existing) {
                $certId = (int) $existing['id'];
            } else {
                $certId = Database::insert('certificates', [
                    'fingerprint_sha256' => $c['fingerprint_sha256'], 'subject' => $c['subject'], 'issuer' => $c['issuer'],
                    'serial' => $c['serial'], 'sans' => json_out($c['sans']), 'not_before' => $c['not_before'], 'not_after' => $c['not_after'],
                    'signature_algorithm' => isset($c['signature_algorithm']) ? mb_substr((string) $c['signature_algorithm'], 0, 60) : null,
                    'key_type' => $c['key_type'], 'key_bits' => $c['key_bits'], 'first_seen' => Database::now(),
                ]);
                $new = true;
            }
        }
        $details = $r;
        foreach ($details['chain'] as &$link) {
            unset($link['pem']);
        }
        unset($link);
        if (isset($details['certificate'])) {
            unset($details['certificate']['pem']);
        }
        $id = Database::insert('tls_checks', [
            'domain_id' => $domainId, 'host' => $r['host'], 'port' => $r['port'], 'ip' => $r['ip'], 'status' => $r['status'],
            'certificate_id' => $certId, 'protocol' => $r['protocol'], 'cipher' => $r['cipher'] ? mb_substr((string) $r['cipher'], 0, 80) : null,
            'chain_trusted' => isset($r['chain_trusted']) ? (int) $r['chain_trusted'] : null,
            'hostname_match' => isset($r['hostname_match']) ? (int) $r['hostname_match'] : null,
            'error' => $r['error'] ? mb_substr((string) $r['error'], 0, 480) : null,
            'details' => json_out($details), 'checked_at' => Database::now(),
        ]);
        // Historie begrenzen
        Database::run(
            'DELETE FROM tls_checks WHERE domain_id = ? AND host = ? AND port = ? AND id NOT IN (
                SELECT id FROM (SELECT id FROM tls_checks WHERE domain_id = ? AND host = ? AND port = ? ORDER BY id DESC LIMIT 30) t)',
            [$domainId, $r['host'], $r['port'], $domainId, $r['host'], $r['port']]
        );
        return [
            'check_id' => $id, 'certificate_id' => $certId, 'new_certificate' => $new,
            'previous_fingerprint' => $prev['fingerprint_sha256'] ?? null,
        ];
    }

    /** @return array<string,mixed>|null */
    public static function latestCheck(int $domainId, string $host, int $port = 443): ?array
    {
        $row = Database::one(
            'SELECT t.*, c.fingerprint_sha256, c.subject, c.issuer, c.not_after, c.not_before, c.sans, c.serial, c.signature_algorithm, c.key_type, c.key_bits
             FROM tls_checks t LEFT JOIN certificates c ON c.id = t.certificate_id
             WHERE t.domain_id = ? AND t.host = ? AND t.port = ? ORDER BY t.id DESC LIMIT 1',
            [$domainId, $host, $port]
        );
        return $row ? self::decode($row) : null;
    }

    /** Neueste Prüfung je Host/Port einer Domain. @return array<int,array<string,mixed>> */
    public static function latestForDomain(int $domainId): array
    {
        $rows = Database::all(
            'SELECT t.*, c.fingerprint_sha256, c.subject, c.issuer, c.not_after, c.not_before, c.sans, c.serial, c.signature_algorithm, c.key_type, c.key_bits
             FROM tls_checks t LEFT JOIN certificates c ON c.id = t.certificate_id
             JOIN (SELECT MAX(id) AS mid FROM tls_checks WHERE domain_id = ? GROUP BY host, port) x ON x.mid = t.id
             ORDER BY t.host, t.port',
            [$domainId]
        );
        return array_map([self::class, 'decode'], $rows);
    }

    /** @return array<int,array<string,mixed>> */
    public static function latestForAll(): array
    {
        $rows = Database::all(
            'SELECT t.*, d.name AS domain_name, c.fingerprint_sha256, c.subject, c.issuer, c.not_after, c.not_before, c.sans, c.serial, c.signature_algorithm, c.key_type, c.key_bits
             FROM tls_checks t JOIN domains d ON d.id = t.domain_id LEFT JOIN certificates c ON c.id = t.certificate_id
             JOIN (SELECT MAX(id) AS mid FROM tls_checks GROUP BY domain_id, host, port) x ON x.mid = t.id
             ORDER BY (c.not_after IS NULL), c.not_after ASC'
        );
        return array_map([self::class, 'decode'], $rows);
    }

    /** @return array<int,array<string,mixed>> */
    public static function history(int $domainId, string $host, int $port = 443, int $limit = 15): array
    {
        $rows = Database::all(
            'SELECT t.*, c.fingerprint_sha256, c.not_after, c.issuer FROM tls_checks t LEFT JOIN certificates c ON c.id = t.certificate_id
             WHERE t.domain_id = ? AND t.host = ? AND t.port = ? ORDER BY t.id DESC LIMIT ' . (int) $limit,
            [$domainId, $host, $port]
        );
        return array_map([self::class, 'decode'], $rows);
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    private static function decode(array $row): array
    {
        $row['details'] = json_decode((string) ($row['details'] ?? 'null'), true) ?: [];
        if (isset($row['sans'])) {
            $row['sans'] = json_decode((string) $row['sans'], true) ?: [];
        }
        return $row;
    }

    public static function count(): int
    {
        return (int) Database::value('SELECT COUNT(*) FROM certificates');
    }
}

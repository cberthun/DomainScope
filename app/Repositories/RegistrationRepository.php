<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class RegistrationRepository
{
    /**
     * Speichert einen Registrierungsabruf (RDAP/WHOIS). Identische Daten aktualisieren nur den Abrufzeitpunkt.
     *
     * @param array<string,mixed> $d
     * @return array{id:int,previous:?array,changed:bool}
     */
    public static function save(int $domainId, array $d): array
    {
        $stable = [
            'registrar' => $d['registrar'] ?? null, 'registered_at' => $d['registered_at'] ?? null, 'changed_at' => $d['changed_at'] ?? null,
            'expires_at' => $d['expires_at'] ?? null, 'statuses' => $d['statuses'] ?? [], 'nameservers' => $d['nameservers'] ?? [],
            'dnssec_signed' => $d['dnssec_signed'] ?? null,
        ];
        $hash = hash('sha256', json_out($stable));
        $prev = self::latest($domainId);
        if ($prev !== null && $prev['content_hash'] === $hash) {
            Database::run('UPDATE registration_snapshots SET fetched_at = ?, data = ? WHERE id = ?', [Database::now(), json_out($d), $prev['id']]);
            return ['id' => (int) $prev['id'], 'previous' => $prev, 'changed' => false];
        }
        $id = Database::insert('registration_snapshots', [
            'domain_id' => $domainId, 'source' => $d['source'] ?? 'rdap', 'source_url' => isset($d['source_url']) ? mb_substr((string) $d['source_url'], 0, 500) : null,
            'registrar' => isset($d['registrar']) ? mb_substr((string) $d['registrar'], 0, 255) : null,
            'registered_at' => $d['registered_at'] ?? null, 'changed_at' => $d['changed_at'] ?? null, 'expires_at' => $d['expires_at'] ?? null,
            'statuses' => json_out($d['statuses'] ?? []), 'nameservers' => json_out($d['nameservers'] ?? []),
            'dnssec_signed' => isset($d['dnssec_signed']) ? (int) $d['dnssec_signed'] : null,
            'content_hash' => $hash, 'data' => json_out($d), 'fetched_at' => Database::now(),
        ]);
        return ['id' => $id, 'previous' => $prev, 'changed' => true];
    }

    /** @return array<string,mixed>|null */
    public static function latest(int $domainId): ?array
    {
        $row = Database::one('SELECT * FROM registration_snapshots WHERE domain_id = ? ORDER BY id DESC LIMIT 1', [$domainId]);
        return $row ? self::decode($row) : null;
    }

    /** @return array<int,array<string,mixed>> */
    public static function history(int $domainId, int $limit = 20): array
    {
        return array_map([self::class, 'decode'], Database::all('SELECT * FROM registration_snapshots WHERE domain_id = ? ORDER BY id DESC LIMIT ' . (int) $limit, [$domainId]));
    }

    /** @return array<int,array<string,mixed>> */
    public static function latestForAll(): array
    {
        $rows = Database::all(
            'SELECT r.*, d.name AS domain_name FROM registration_snapshots r
             JOIN domains d ON d.id = r.domain_id
             JOIN (SELECT domain_id, MAX(id) AS mid FROM registration_snapshots GROUP BY domain_id) x ON x.mid = r.id
             ORDER BY (r.expires_at IS NULL), r.expires_at ASC'
        );
        return array_map([self::class, 'decode'], $rows);
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    private static function decode(array $row): array
    {
        foreach (['statuses', 'nameservers', 'data'] as $k) {
            $row[$k] = json_decode((string) ($row[$k] ?? 'null'), true) ?: [];
        }
        return $row;
    }
}

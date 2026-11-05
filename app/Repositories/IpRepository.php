<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;
use DomainScope\Validation\IpClassifier;

final class IpRepository
{
    /** @param array<string,mixed> $info Ergebnis von IpIntelligenceService::lookup() */
    public static function saveLookup(array $info): int
    {
        $ip = $info['ip'];
        $bgp = $info['bgp'] ?? null;
        $asn = $info['asn_info'] ?? null;
        $reg = $info['registration'] ?? null;
        $now = Database::now();
        $data = [
            'version' => (int) $info['version'], 'classification' => $info['classification']['category'],
            'reverse_dns' => $info['reverse_dns']['names'][0] ?? null,
            'asn' => $bgp['asns'][0] ?? null, 'as_name' => isset($asn['name']) ? mb_substr((string) $asn['name'], 0, 255) : null,
            'prefix' => $bgp['prefix'] ?? null, 'country' => $bgp['country'] ?? null, 'registry' => $bgp['registry'] ?? null,
            'rdap_name' => isset($reg['name']) ? mb_substr((string) $reg['name'], 0, 255) : null,
            'rdap_data' => $reg && ($reg['ok'] ?? false) ? json_out($reg) : null,
            'data_sources' => json_out($info['sources'] ?? []), 'checked_at' => $now,
        ];
        $existing = Database::one('SELECT id FROM ip_addresses WHERE address = ?', [$ip]);
        if ($existing) {
            Database::update('ip_addresses', $data, 'id = ?', [$existing['id']]);
            return (int) $existing['id'];
        }
        return Database::insert('ip_addresses', $data + ['address' => $ip, 'first_seen' => $now]);
    }

    /** Stellt sicher, dass eine IP existiert (ohne Anreicherung). */
    public static function ensure(string $ip): int
    {
        $ip = IpClassifier::normalize($ip) ?? $ip;
        $row = Database::one('SELECT id FROM ip_addresses WHERE address = ?', [$ip]);
        if ($row) {
            return (int) $row['id'];
        }
        return Database::insert('ip_addresses', [
            'address' => $ip, 'version' => IpClassifier::version($ip) ?? 4,
            'classification' => IpClassifier::classify($ip)['category'], 'first_seen' => Database::now(),
        ]);
    }

    public static function link(int $domainId, int $ipId, string $hostname, string $recordType, string $source = 'dns'): void
    {
        $now = Database::now();
        Database::run(
            'INSERT INTO domain_ips (domain_id, ip_id, hostname, record_type, source, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)
             ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen), record_type = VALUES(record_type)',
            [$domainId, $ipId, mb_substr($hostname, 0, 253), $recordType, $source, $now, $now]
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function forDomain(int $domainId): array
    {
        return Database::all(
            'SELECT i.*, di.hostname, di.record_type, di.source, di.first_seen AS linked_first, di.last_seen AS linked_last
             FROM domain_ips di JOIN ip_addresses i ON i.id = di.ip_id WHERE di.domain_id = ? ORDER BY di.hostname, i.address',
            [$domainId]
        );
    }

    /** @return array<string,mixed>|null */
    public static function find(string $ip): ?array
    {
        $row = Database::one('SELECT * FROM ip_addresses WHERE address = ?', [IpClassifier::normalize($ip) ?? $ip]);
        if ($row) {
            $row['rdap_data'] = json_decode((string) ($row['rdap_data'] ?? 'null'), true) ?: null;
            $row['data_sources'] = json_decode((string) ($row['data_sources'] ?? '[]'), true) ?: [];
        }
        return $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function domainsFor(int $ipId): array
    {
        return Database::all(
            'SELECT di.hostname, di.record_type, di.last_seen, d.name AS domain_name FROM domain_ips di JOIN domains d ON d.id = di.domain_id WHERE di.ip_id = ? ORDER BY di.hostname',
            [$ipId]
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function all(string $q = '', int $limit = 500): array
    {
        $sql = 'SELECT i.*, (SELECT COUNT(DISTINCT di.hostname) FROM domain_ips di WHERE di.ip_id = i.id) AS host_count FROM ip_addresses i';
        $params = [];
        if ($q !== '') {
            $sql .= ' WHERE i.address LIKE ? OR i.as_name LIKE ? OR i.reverse_dns LIKE ?';
            $like = '%' . addcslashes($q, '%_\\') . '%';
            $params = [$like, $like, $like];
        }
        return Database::all($sql . ' ORDER BY i.asn, i.address LIMIT ' . (int) $limit, $params);
    }

    public static function countAll(): int
    {
        return (int) Database::value('SELECT COUNT(*) FROM ip_addresses');
    }
}

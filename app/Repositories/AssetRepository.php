<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class AssetRepository
{
    public const TYPES = [
        'domain' => 'Domain', 'subdomain' => 'Subdomain', 'ip' => 'IP-Adresse', 'server' => 'Server', 'vps' => 'VPS',
        'mailserver' => 'Mailserver', 'webserver' => 'Webserver', 'reverse_proxy' => 'Reverse Proxy', 'tunnel' => 'Tunnel-Endpunkt',
        'nameserver' => 'Nameserver', 'certificate' => 'Zertifikat', 'application' => 'Anwendung', 'external_service' => 'Externer Dienst',
    ];
    public const ENVIRONMENTS = ['production' => 'Produktion', 'staging' => 'Staging', 'development' => 'Entwicklung', 'test' => 'Test', 'other' => 'Sonstige'];
    public const RELATIONS = [
        'depends_on' => 'hängt ab von', 'runs_on' => 'läuft auf', 'resolves_to' => 'löst auf zu', 'served_by' => 'wird bedient von',
        'proxied_by' => 'läuft hinter', 'mail_via' => 'Mail über', 'secured_by' => 'abgesichert durch', 'delegated_to' => 'delegiert an', 'related' => 'in Beziehung zu',
    ];

    /** @param array<string,mixed> $d */
    public static function create(array $d): int
    {
        $now = Database::now();
        return Database::insert('assets', self::clean($d) + ['created_at' => $now, 'updated_at' => $now]);
    }

    /** @param array<string,mixed> $d */
    public static function update(int $id, array $d): void
    {
        Database::update('assets', self::clean($d) + ['updated_at' => Database::now()], 'id = ?', [$id]);
    }

    /** @param array<string,mixed> $d @return array<string,mixed> */
    private static function clean(array $d): array
    {
        $type = isset(self::TYPES[$d['type'] ?? '']) ? $d['type'] : 'server';
        $env = isset(self::ENVIRONMENTS[$d['environment'] ?? '']) ? $d['environment'] : 'production';
        $tags = implode(', ', array_slice(array_unique(array_filter(array_map(
            static fn($t) => mb_substr(trim($t), 0, 30),
            explode(',', (string) ($d['tags'] ?? ''))
        ))), 0, 15));
        return [
            'name' => mb_substr(trim((string) $d['name']), 0, 200), 'type' => $type,
            'address' => ($a = trim((string) ($d['address'] ?? ''))) !== '' ? mb_substr($a, 0, 253) : null,
            'description' => ($x = trim((string) ($d['description'] ?? ''))) !== '' ? mb_substr($x, 0, 5000) : null,
            'provider' => ($p = trim((string) ($d['provider'] ?? ''))) !== '' ? mb_substr($p, 0, 150) : null,
            'environment' => $env, 'tags' => $tags,
            'notes' => ($n = trim((string) ($d['notes'] ?? ''))) !== '' ? mb_substr($n, 0, 10000) : null,
            'domain_id' => !empty($d['domain_id']) ? (int) $d['domain_id'] : null,
        ];
    }

    public static function delete(int $id): void
    {
        Database::run('DELETE FROM assets WHERE id = ?', [$id]);
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        return Database::one('SELECT a.*, d.name AS domain_name, COALESCE(a.last_checked_at, d.last_checked_at) AS last_checked_at FROM assets a LEFT JOIN domains d ON d.id = a.domain_id WHERE a.id = ?', [$id]);
    }

    /** @return array<int,array<string,mixed>> */
    public static function all(array $f = []): array
    {
        $where = [];
        $params = [];
        if (!empty($f['type'])) {
            $where[] = 'a.type = ?';
            $params[] = $f['type'];
        }
        if (!empty($f['environment'])) {
            $where[] = 'a.environment = ?';
            $params[] = $f['environment'];
        }
        if (!empty($f['q'])) {
            $where[] = '(a.name LIKE ? OR a.address LIKE ? OR a.tags LIKE ? OR a.provider LIKE ?)';
            $like = '%' . addcslashes($f['q'], '%_\\') . '%';
            array_push($params, $like, $like, $like, $like);
        }
        return Database::all(
            'SELECT a.*, d.name AS domain_name, COALESCE(a.last_checked_at, d.last_checked_at) AS last_checked_at,
                (SELECT COUNT(*) FROM asset_relationships r WHERE r.from_asset_id = a.id OR r.to_asset_id = a.id) AS rel_count
             FROM assets a LEFT JOIN domains d ON d.id = a.domain_id' . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY a.type, a.name',
            $params
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function relationships(?int $assetId = null): array
    {
        $sql = 'SELECT r.*, f.name AS from_name, f.type AS from_type, t.name AS to_name, t.type AS to_type
                FROM asset_relationships r JOIN assets f ON f.id = r.from_asset_id JOIN assets t ON t.id = r.to_asset_id';
        $params = [];
        if ($assetId) {
            $sql .= ' WHERE r.from_asset_id = ? OR r.to_asset_id = ?';
            $params = [$assetId, $assetId];
        }
        return Database::all($sql . ' ORDER BY r.id', $params);
    }

    public static function link(int $from, int $to, string $relation, string $origin = 'manual', bool $confirmed = true, ?string $note = null): bool
    {
        if ($from === $to || !isset(self::RELATIONS[$relation])) {
            return false;
        }
        $n = Database::run(
            'INSERT IGNORE INTO asset_relationships (from_asset_id, to_asset_id, relation, origin, confirmed, note, created_at) VALUES (?,?,?,?,?,?,?)',
            [$from, $to, $relation, $origin, (int) $confirmed, $note !== null ? mb_substr($note, 0, 250) : null, Database::now()]
        )->rowCount();
        return $n > 0;
    }

    public static function confirm(int $relId): void
    {
        Database::run("UPDATE asset_relationships SET confirmed = 1, origin = 'manual' WHERE id = ?", [$relId]);
    }

    public static function unlink(int $relId): void
    {
        Database::run('DELETE FROM asset_relationships WHERE id = ?', [$relId]);
    }

    public static function countAll(): int
    {
        return (int) Database::value('SELECT COUNT(*) FROM assets');
    }

    /** @return array<string,mixed>|null */
    public static function findByAddress(string $type, string $address): ?array
    {
        return Database::one('SELECT * FROM assets WHERE type = ? AND address = ?', [$type, $address]);
    }
}

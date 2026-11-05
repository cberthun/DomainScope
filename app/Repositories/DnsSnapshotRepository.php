<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Services\DNS\RecordFormatter;
use DomainScope\Support\Database;

/** DNS-Snapshots und Vergleich. Identische Zustände werden nicht erneut gespeichert (nur Prüfzeitpunkt aktualisiert). */
final class DnsSnapshotRepository
{
    /**
     * @param array<int,array{name:string,type:string,ttl:int,data:string}> $records
     * @param array<string,string> $errors  Typ => Fehlertext
     * @return array{snapshot_id:int,changed:bool,previous_id:?int,added:array,removed:array}
     */
    public static function store(int $domainId, string $host, string $resolver, array $records, array $errors = []): array
    {
        $keys = [];
        $clean = [];
        foreach ($records as $r) {
            $k = RecordFormatter::canonicalKey($r);
            if (!isset($keys[$k])) {
                $keys[$k] = true;
                $clean[] = $r;
            }
        }
        ksort($keys);
        $hash = hash('sha256', implode("\n", array_keys($keys)));
        $prev = Database::one(
            'SELECT * FROM dns_snapshots WHERE domain_id = ? AND host = ? AND resolver = ? ORDER BY id DESC LIMIT 1',
            [$domainId, $host, $resolver]
        );
        // Bei Fehlern (z. B. Timeout für einen Typ) ist der Zustand unvollständig → nicht als Änderung werten
        if ($prev !== null && $prev['content_hash'] === $hash) {
            Database::run('UPDATE dns_snapshots SET taken_at = ?, errors = ? WHERE id = ?', [Database::now(), $errors ? json_out($errors) : null, $prev['id']]);
            return ['snapshot_id' => (int) $prev['id'], 'changed' => false, 'previous_id' => (int) $prev['id'], 'added' => [], 'removed' => []];
        }
        return Database::transaction(static function () use ($domainId, $host, $resolver, $clean, $errors, $hash, $prev): array {
            $id = Database::insert('dns_snapshots', [
                'domain_id' => $domainId, 'host' => $host, 'resolver' => $resolver, 'content_hash' => $hash,
                'record_count' => count($clean), 'errors' => $errors ? json_out($errors) : null, 'taken_at' => Database::now(),
            ]);
            foreach (array_chunk($clean, 100) as $chunk) {
                $ph = implode(',', array_fill(0, count($chunk), '(?,?,?,?,?)'));
                $params = [];
                foreach ($chunk as $r) {
                    array_push($params, $id, mb_substr($r['name'], 0, 253), $r['type'], $r['ttl'], $r['data']);
                }
                Database::run("INSERT INTO dns_records (snapshot_id, name, type, ttl, data) VALUES $ph", $params);
            }
            $diff = $prev ? self::diff((int) $prev['id'], $id) : ['added' => [], 'removed' => []];
            return ['snapshot_id' => $id, 'changed' => true, 'previous_id' => $prev ? (int) $prev['id'] : null] + $diff;
        });
    }

    /** @return array<int,array<string,mixed>> */
    public static function records(int $snapshotId): array
    {
        return Database::all('SELECT name, type, ttl, data FROM dns_records WHERE snapshot_id = ? ORDER BY type, name, data', [$snapshotId]);
    }

    /** @return array{added:array,removed:array} */
    public static function diff(int $oldId, int $newId): array
    {
        $key = static fn(array $r) => strtolower($r['name']) . "\t" . $r['type'] . "\t" . $r['data'];
        $old = [];
        foreach (self::records($oldId) as $r) {
            $old[$key($r)] = $r;
        }
        $new = [];
        foreach (self::records($newId) as $r) {
            $new[$key($r)] = $r;
        }
        return [
            'added' => array_values(array_diff_key($new, $old)),
            'removed' => array_values(array_diff_key($old, $new)),
        ];
    }

    /** @return array<int,array<string,mixed>> */
    public static function list(int $domainId, ?string $host = null, int $limit = 50): array
    {
        $sql = 'SELECT * FROM dns_snapshots WHERE domain_id = ?' . ($host ? ' AND host = ?' : '') . ' ORDER BY id DESC LIMIT ' . (int) $limit;
        return Database::all($sql, $host ? [$domainId, $host] : [$domainId]);
    }

    /** @return array<string,mixed>|null */
    public static function latest(int $domainId, string $host, string $resolver): ?array
    {
        return Database::one('SELECT * FROM dns_snapshots WHERE domain_id = ? AND host = ? AND resolver = ? ORDER BY id DESC LIMIT 1', [$domainId, $host, $resolver]);
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        return Database::one('SELECT s.*, d.name AS domain_name FROM dns_snapshots s JOIN domains d ON d.id = s.domain_id WHERE s.id = ?', [$id]);
    }
}

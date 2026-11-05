<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class ActivityRepository
{
    public static function log(string $type, string $message, ?int $domainId = null): void
    {
        try {
            Database::insert('activity_log', [
                'type' => $type, 'message' => mb_substr($message, 0, 480), 'domain_id' => $domainId, 'created_at' => Database::now(),
            ]);
            Database::run('DELETE FROM activity_log WHERE created_at < ?', [gmdate('Y-m-d H:i:s', time() - 90 * 86400)]);
        } catch (\Throwable) {
        }
    }

    /** @return array<int,array<string,mixed>> */
    public static function recent(int $limit = 15): array
    {
        return Database::all(
            'SELECT a.*, d.name AS domain_name FROM activity_log a LEFT JOIN domains d ON d.id = a.domain_id ORDER BY a.id DESC LIMIT ' . (int) $limit
        );
    }

    public static function change(int $domainId, string $type, string $summary, array $detail = []): void
    {
        Database::insert('change_events', [
            'domain_id' => $domainId, 'type' => $type, 'summary' => mb_substr($summary, 0, 480),
            'detail' => $detail ? json_out($detail) : null, 'detected_at' => Database::now(),
        ]);
        self::log('change', $summary, $domainId);
    }

    /** @return array<int,array<string,mixed>> */
    public static function changes(?int $domainId = null, int $limit = 100, ?string $type = null): array
    {
        $where = [];
        $params = [];
        if ($domainId) {
            $where[] = 'c.domain_id = ?';
            $params[] = $domainId;
        }
        if ($type) {
            $where[] = 'c.type LIKE ?';
            $params[] = $type . '%';
        }
        $sql = 'SELECT c.*, d.name AS domain_name FROM change_events c JOIN domains d ON d.id = c.domain_id'
            . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY c.id DESC LIMIT ' . (int) $limit;
        return Database::all($sql, $params);
    }
}

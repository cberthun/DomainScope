<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

/** Strukturierte Prüfergebnisse (E-Mail, DNSSEC, HTTP …) mit Historie. */
final class ModuleResultRepository
{
    private const KEEP = 30;

    /**
     * @param array<string,mixed> $data
     * @return array{id:int,previous:?array}
     */
    public static function save(int $domainId, string $module, string $subject, string $status, ?string $summary, array $data, ?int $durationMs = null): array
    {
        $prev = self::latest($domainId, $module, $subject);
        $stable = $data;
        unset($stable['checked_at'], $stable['duration_ms'], $stable['dns_queries'], $stable['ms']);
        $hash = hash('sha256', json_out($stable));
        $id = Database::insert('module_results', [
            'domain_id' => $domainId, 'module' => $module, 'subject' => $subject, 'status' => $status,
            'summary' => $summary !== null ? mb_substr($summary, 0, 480) : null, 'content_hash' => $hash,
            'data' => json_out($data), 'duration_ms' => $durationMs, 'checked_at' => Database::now(),
        ]);
        Database::run(
            'DELETE FROM module_results WHERE domain_id = ? AND module = ? AND subject = ? AND id NOT IN (
                SELECT id FROM (SELECT id FROM module_results WHERE domain_id = ? AND module = ? AND subject = ? ORDER BY id DESC LIMIT ' . self::KEEP . ') t)',
            [$domainId, $module, $subject, $domainId, $module, $subject]
        );
        return ['id' => $id, 'previous' => $prev];
    }

    /** @return array<string,mixed>|null  Zeile mit dekodiertem 'data' */
    public static function latest(int $domainId, string $module, string $subject = ''): ?array
    {
        $row = Database::one(
            'SELECT * FROM module_results WHERE domain_id = ? AND module = ? AND subject = ? ORDER BY id DESC LIMIT 1',
            [$domainId, $module, $subject]
        );
        return $row ? self::decode($row) : null;
    }

    /** @return array<int,array<string,mixed>> */
    public static function history(int $domainId, string $module, string $subject = '', int $limit = 20): array
    {
        return array_map([self::class, 'decode'], Database::all(
            'SELECT * FROM module_results WHERE domain_id = ? AND module = ? AND subject = ? ORDER BY id DESC LIMIT ' . (int) $limit,
            [$domainId, $module, $subject]
        ));
    }

    /** Letzte Ergebnisse eines Moduls für alle Domains. @return array<int,array<string,mixed>> */
    public static function latestForAll(string $module): array
    {
        $rows = Database::all(
            'SELECT m.* FROM module_results m
             JOIN (SELECT domain_id, MAX(id) AS mid FROM module_results WHERE module = ? AND subject = \'\' GROUP BY domain_id) x ON x.mid = m.id',
            [$module]
        );
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['domain_id']] = self::decode($r);
        }
        return $out;
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    private static function decode(array $row): array
    {
        $row['data'] = json_decode((string) $row['data'], true) ?: [];
        return $row;
    }
}

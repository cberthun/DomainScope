<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class FindingRepository
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    public const STATUSES = ['open', 'acknowledged', 'ignored', 'resolved'];

    /**
     * Gleicht Findings eines Moduls einer Domain mit den aktuell ermittelten Entwürfen ab.
     *
     * @param array<int,array<string,mixed>> $drafts
     * @return array{created:int,updated:int,resolved:int,reopened:int}
     */
    public static function reconcile(int $domainId, string $module, array $drafts): array
    {
        $stats = ['created' => 0, 'updated' => 0, 'resolved' => 0, 'reopened' => 0];
        $now = Database::now();
        return Database::transaction(static function () use ($domainId, $module, $drafts, $now, &$stats): array {
            $seen = [];
            foreach ($drafts as $d) {
                $fp = self::fingerprint($d['rule_id'], $domainId, $d['subject'] ?? '');
                $seen[$fp] = true;
                $row = Database::one('SELECT * FROM findings WHERE fingerprint = ?', [$fp]);
                $evidence = isset($d['evidence']) ? json_out($d['evidence']) : null;
                if ($row === null) {
                    $id = Database::insert('findings', [
                        'fingerprint' => $fp, 'rule_id' => $d['rule_id'], 'module' => $module, 'domain_id' => $domainId,
                        'subject' => mb_substr((string) ($d['subject'] ?? ''), 0, 253), 'title' => mb_substr($d['title'], 0, 250),
                        'category' => $d['category'], 'severity' => $d['severity'], 'status' => 'open',
                        'reasoning' => $d['reasoning'], 'recommendation' => $d['recommendation'], 'evidence' => $evidence,
                        'source' => mb_substr($d['source'], 0, 60), 'first_seen' => $now, 'last_seen' => $now,
                    ]);
                    self::event($id, 'created', 'Schweregrad: ' . $d['severity']);
                    $stats['created']++;
                    continue;
                }
                $update = [
                    'title' => mb_substr($d['title'], 0, 250), 'severity' => $d['severity'], 'reasoning' => $d['reasoning'],
                    'recommendation' => $d['recommendation'], 'evidence' => $evidence, 'source' => mb_substr($d['source'], 0, 60),
                    'last_seen' => $now, 'category' => $d['category'],
                ];
                if ($row['status'] === 'resolved') {
                    $update += ['status' => 'open', 'resolved_at' => null];
                    self::event((int) $row['id'], 'reopened', 'Problem tritt erneut auf');
                    $stats['reopened']++;
                } else {
                    if ($row['severity'] !== $d['severity']) {
                        self::event((int) $row['id'], 'severity_changed', $row['severity'] . ' → ' . $d['severity']);
                    }
                    $stats['updated']++;
                }
                Database::update('findings', $update, 'id = ?', [$row['id']]);
            }
            $open = Database::all(
                "SELECT id, fingerprint FROM findings WHERE domain_id = ? AND module = ? AND status IN ('open','acknowledged')",
                [$domainId, $module]
            );
            foreach ($open as $o) {
                if (!isset($seen[$o['fingerprint']])) {
                    Database::update('findings', ['status' => 'resolved', 'resolved_at' => $now], 'id = ?', [$o['id']]);
                    self::event((int) $o['id'], 'auto_resolved', 'Bei der letzten Prüfung nicht mehr festgestellt');
                    $stats['resolved']++;
                }
            }
            return $stats;
        });
    }

    public static function fingerprint(string $ruleId, int $domainId, string $subject): string
    {
        return sha1($ruleId . '|' . $domainId . '|' . strtolower($subject));
    }

    public static function event(int $findingId, string $event, ?string $detail = null): void
    {
        Database::insert('finding_events', ['finding_id' => $findingId, 'event' => $event, 'detail' => $detail !== null ? mb_substr($detail, 0, 480) : null, 'created_at' => Database::now()]);
    }

    public static function setStatus(int $id, string $status, ?string $note = null): bool
    {
        if (!in_array($status, self::STATUSES, true)) {
            return false;
        }
        $row = Database::one('SELECT status FROM findings WHERE id = ?', [$id]);
        if ($row === null) {
            return false;
        }
        Database::update('findings', ['status' => $status, 'resolved_at' => $status === 'resolved' ? Database::now() : null], 'id = ?', [$id]);
        self::event($id, 'status_' . $status, ($note ? $note . ' – ' : '') . 'manuell von ' . $row['status'] . ' auf ' . $status);
        return true;
    }

    /**
     * @param array{status?:string,severity?:string,domain_id?:int,module?:string,q?:string} $f
     * @return array<int,array<string,mixed>>
     */
    public static function search(array $f = [], int $limit = 500): array
    {
        $where = [];
        $params = [];
        if (!empty($f['status'])) {
            if ($f['status'] === 'active') {
                $where[] = "f.status IN ('open','acknowledged')";
            } else {
                $where[] = 'f.status = ?';
                $params[] = $f['status'];
            }
        }
        foreach (['severity', 'module'] as $k) {
            if (!empty($f[$k])) {
                $where[] = "f.$k = ?";
                $params[] = $f[$k];
            }
        }
        if (!empty($f['domain_id'])) {
            $where[] = 'f.domain_id = ?';
            $params[] = (int) $f['domain_id'];
        }
        if (!empty($f['q'])) {
            $where[] = '(f.title LIKE ? OR f.subject LIKE ? OR f.rule_id LIKE ?)';
            $like = '%' . addcslashes($f['q'], '%_\\') . '%';
            array_push($params, $like, $like, $like);
        }
        $sql = "SELECT f.*, d.name AS domain_name FROM findings f LEFT JOIN domains d ON d.id = f.domain_id"
            . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
            . " ORDER BY FIELD(f.severity,'critical','high','medium','low','unknown','info'), f.last_seen DESC LIMIT " . (int) $limit;
        return array_map([self::class, 'decode'], Database::all($sql, $params));
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        $row = Database::one('SELECT f.*, d.name AS domain_name FROM findings f LEFT JOIN domains d ON d.id = f.domain_id WHERE f.id = ?', [$id]);
        return $row ? self::decode($row) : null;
    }

    /** @return array<int,array<string,mixed>> */
    public static function events(int $id): array
    {
        return Database::all('SELECT * FROM finding_events WHERE finding_id = ? ORDER BY id DESC', [$id]);
    }

    /** @return array<string,int> */
    public static function countsBySeverity(): array
    {
        $out = array_fill_keys(self::SEVERITIES, 0);
        foreach (Database::all("SELECT severity, COUNT(*) c FROM findings WHERE status IN ('open','acknowledged') GROUP BY severity") as $r) {
            $out[$r['severity']] = (int) $r['c'];
        }
        return $out;
    }

    /** @param array<string,mixed> $row @return array<string,mixed> */
    private static function decode(array $row): array
    {
        $row['evidence'] = json_decode((string) ($row['evidence'] ?? 'null'), true);
        return $row;
    }
}

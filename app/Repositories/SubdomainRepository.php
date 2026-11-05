<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

final class SubdomainRepository
{
    /**
     * Speichert einen Scan, dedupliziert und markiert neue/nicht mehr gefundene Einträge.
     *
     * @param array{hosts:array<string,array>,wildcards:string[],sources:array,errors:array} $found
     * @return array{scan_id:int,new:string[],missing:string[],returned:string[],total:int,partial:bool}
     */
    public static function saveScan(int $domainId, array $found): array
    {
        $now = Database::now();
        $partial = $found['errors'] !== [];
        return Database::transaction(static function () use ($domainId, $found, $now, $partial): array {
            $hosts = array_keys($found['hosts']);
            $existing = [];
            foreach (Database::all('SELECT hostname, status, first_seen_scan_id FROM subdomains WHERE domain_id = ?', [$domainId]) as $row) {
                $existing[$row['hostname']] = $row;
            }
            $firstScan = Database::value('SELECT COUNT(*) FROM subdomain_scans WHERE domain_id = ?', [$domainId]) == 0;
            $scanId = Database::insert('subdomain_scans', [
                'domain_id' => $domainId, 'sources' => json_out(array_keys($found['sources'])), 'found_count' => count($hosts),
                'new_count' => 0, 'missing_count' => 0, 'errors' => $found['errors'] ? json_out($found['errors']) : null, 'scanned_at' => $now,
            ]);
            $new = [];
            $returned = [];
            foreach ($found['hosts'] as $host => $meta) {
                $sources = json_out(array_keys($meta['sources']));
                if (!isset($existing[$host])) {
                    Database::insert('subdomains', [
                        'domain_id' => $domainId, 'hostname' => $host, 'is_wildcard' => 0, 'sources' => $sources,
                        'first_seen_scan_id' => $scanId, 'last_seen_scan_id' => $scanId, 'first_seen' => $now, 'last_seen' => $now,
                        'status' => 'present', 'cert_not_after' => $meta['not_after'],
                    ]);
                    if (!$firstScan) {
                        $new[] = $host;
                    }
                } else {
                    if ($existing[$host]['status'] === 'missing') {
                        $returned[] = $host;
                    }
                    Database::run(
                        'UPDATE subdomains SET last_seen_scan_id = ?, last_seen = ?, status = \'present\', sources = ?, cert_not_after = ? WHERE domain_id = ? AND hostname = ?',
                        [$scanId, $now, $sources, $meta['not_after'], $domainId, $host]
                    );
                }
            }
            // "Nicht mehr gefunden" nur bewerten, wenn alle Quellen erfolgreich waren (sonst unvollständige Basis)
            $missing = [];
            if (!$partial) {
                foreach ($existing as $host => $row) {
                    if (!isset($found['hosts'][$host]) && $row['status'] === 'present') {
                        $missing[] = $host;
                    }
                }
                if ($missing) {
                    $ph = implode(',', array_fill(0, count($missing), '?'));
                    Database::run("UPDATE subdomains SET status = 'missing' WHERE domain_id = ? AND hostname IN ($ph)", [$domainId, ...$missing]);
                }
            }
            Database::run('UPDATE subdomain_scans SET new_count = ?, missing_count = ? WHERE id = ?', [count($new), count($missing), $scanId]);
            return ['scan_id' => $scanId, 'new' => $new, 'missing' => $missing, 'returned' => $returned, 'total' => count($hosts), 'partial' => $partial];
        });
    }

    /** @return array<int,array<string,mixed>> */
    public static function forDomain(int $domainId): array
    {
        $rows = Database::all('SELECT * FROM subdomains WHERE domain_id = ? ORDER BY hostname', [$domainId]);
        $lastScan = (int) Database::value('SELECT MAX(id) FROM subdomain_scans WHERE domain_id = ?', [$domainId]);
        foreach ($rows as &$r) {
            $r['sources'] = json_decode((string) $r['sources'], true) ?: [];
            $r['resolved_ips'] = json_decode((string) ($r['resolved_ips'] ?? '[]'), true) ?: [];
            $r['is_new'] = $lastScan > 0 && (int) $r['first_seen_scan_id'] === $lastScan && $lastScan !== (int) Database::value('SELECT MIN(id) FROM subdomain_scans WHERE domain_id = ?', [$domainId]);
        }
        return $rows;
    }

    /** @return array<int,array<string,mixed>> */
    public static function scans(int $domainId, int $limit = 20): array
    {
        $rows = Database::all('SELECT * FROM subdomain_scans WHERE domain_id = ? ORDER BY id DESC LIMIT ' . (int) $limit, [$domainId]);
        foreach ($rows as &$r) {
            $r['sources'] = json_decode((string) $r['sources'], true) ?: [];
            $r['errors'] = json_decode((string) ($r['errors'] ?? '[]'), true) ?: [];
        }
        return $rows;
    }

    /** @param array<string,array{status:string,ips:string[],cname:?string}> $resolved */
    public static function saveResolution(int $domainId, array $resolved): void
    {
        $now = Database::now();
        foreach ($resolved as $host => $r) {
            Database::run(
                'UPDATE subdomains SET resolved_ips = ?, resolved_cname = ?, resolved_status = ?, resolved_at = ? WHERE domain_id = ? AND hostname = ?',
                [json_out($r['ips']), $r['cname'], $r['status'], $now, $domainId, $host]
            );
        }
    }

    public static function countAll(): int
    {
        return (int) Database::value("SELECT COUNT(*) FROM subdomains WHERE status = 'present'");
    }
}

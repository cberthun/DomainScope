<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

/** Aggregierte Kennzahlen für das Dashboard (ausschließlich aus gespeicherten Echtdaten). */
final class StatsRepository
{
    /** @return array<string,mixed> */
    public static function dashboard(int $certWarnDays = 30): array
    {
        $since7 = gmdate('Y-m-d H:i:s', time() - 7 * 86400);
        $s = [];
        $s['domains'] = (int) Database::value('SELECT COUNT(*) FROM domains');
        $s['monitored'] = (int) Database::value('SELECT COUNT(*) FROM domains WHERE monitored = 1');
        $s['subdomains'] = (int) Database::value("SELECT COUNT(*) FROM subdomains WHERE status = 'present'");
        $s['ips'] = (int) Database::value('SELECT COUNT(*) FROM ip_addresses');
        // Nameserver / Mailserver aus den jeweils neuesten Apex-Snapshots (distinct)
        $latestApex = 'SELECT MAX(s.id) AS mx FROM dns_snapshots s JOIN domains d ON d.id = s.domain_id AND s.host = d.name GROUP BY s.domain_id, s.resolver';
        $s['nameservers'] = (int) Database::value("SELECT COUNT(DISTINCT r.data) FROM dns_records r WHERE r.type = 'NS' AND r.snapshot_id IN (SELECT mx FROM ($latestApex) t)", []) ?: 0;
        $s['mailservers'] = (int) Database::value("SELECT COUNT(DISTINCT SUBSTRING_INDEX(r.data, ' ', -1)) FROM dns_records r WHERE r.type = 'MX' AND r.snapshot_id IN (SELECT mx FROM ($latestApex) t)", []) ?: 0;
        $s['certificates'] = (int) Database::value('SELECT COUNT(*) FROM certificates');
        $s['expiring_certs'] = (int) Database::value(
            'SELECT COUNT(*) FROM tls_checks t JOIN certificates c ON c.id = t.certificate_id
             JOIN (SELECT MAX(id) AS mid FROM tls_checks GROUP BY domain_id, host, port) x ON x.mid = t.id
             WHERE c.not_after <= ?', [gmdate('Y-m-d H:i:s', time() + $certWarnDays * 86400)]
        );
        $s['failed_jobs'] = (int) Database::value("SELECT COUNT(*) FROM scan_jobs WHERE status IN ('failed','partial') AND started_at >= ?", [$since7]);
        $s['jobs_7d'] = (int) Database::value('SELECT COUNT(*) FROM scan_jobs WHERE started_at >= ?', [$since7]);
        $s['new_findings'] = (int) Database::value('SELECT COUNT(*) FROM findings WHERE first_seen >= ?', [$since7]);
        $s['open_findings'] = (int) Database::value("SELECT COUNT(*) FROM findings WHERE status IN ('open','acknowledged')");
        $s['dns_changes'] = (int) Database::value("SELECT COUNT(*) FROM change_events WHERE detected_at >= ? AND (type LIKE 'dns.%' OR type LIKE 'ip.%')", [$since7]);
        $s['email_issues'] = (int) Database::value("SELECT COUNT(*) FROM findings WHERE module = 'email' AND status IN ('open','acknowledged') AND severity IN ('critical','high','medium')");
        $s['dnssec'] = ['signed' => 0, 'unsigned' => 0, 'broken' => 0, 'other' => 0, 'unchecked' => 0];
        $rows = Database::all("SELECT m.data FROM module_results m JOIN (SELECT domain_id, MAX(id) mid FROM module_results WHERE module = 'dnssec' GROUP BY domain_id) x ON x.mid = m.id");
        foreach ($rows as $row) {
            $state = (string) (json_decode($row['data'], true)['state'] ?? '');
            $key = match ($state) { 'signed' => 'signed', 'unsigned' => 'unsigned', 'broken' => 'broken', default => 'other' };
            $s['dnssec'][$key]++;
        }
        $s['dnssec']['unchecked'] = max(0, $s['domains'] - count($rows));
        return $s;
    }

    /** @return array<int,array<string,mixed>> */
    public static function recentJobs(int $limit = 8): array
    {
        return Database::all(
            'SELECT j.*, d.name AS domain_name FROM scan_jobs j LEFT JOIN domains d ON d.id = j.domain_id ORDER BY j.id DESC LIMIT ' . (int) $limit
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function failedResults(int $limit = 8): array
    {
        return Database::all(
            "SELECT r.module, r.message, j.started_at, d.name AS domain_name FROM scan_results r JOIN scan_jobs j ON j.id = r.job_id
             LEFT JOIN domains d ON d.id = j.domain_id WHERE r.status = 'failed' ORDER BY r.id DESC LIMIT " . (int) $limit
        );
    }

    /** @return array<int,array<string,mixed>> */
    public static function dataSources(): array
    {
        return Database::all('SELECT * FROM data_source_status ORDER BY name');
    }

    /** Zeitleiste: Änderungen und neue Findings der letzten Tage. @return array<int,array<string,mixed>> */
    public static function timeline(int $limit = 20): array
    {
        $changes = Database::all(
            "SELECT 'change' AS kind, c.detected_at AS at, c.type, c.summary AS text, d.name AS domain_name, NULL AS severity, NULL AS ref_id
             FROM change_events c JOIN domains d ON d.id = c.domain_id ORDER BY c.id DESC LIMIT " . (int) $limit
        );
        $findings = Database::all(
            "SELECT 'finding' AS kind, f.first_seen AS at, f.rule_id AS type, f.title AS text, d.name AS domain_name, f.severity, f.id AS ref_id
             FROM findings f LEFT JOIN domains d ON d.id = f.domain_id ORDER BY f.id DESC LIMIT " . (int) $limit
        );
        $all = array_merge($changes, $findings);
        usort($all, static fn($a, $b) => strcmp($b['at'], $a['at']));
        return array_slice($all, 0, $limit);
    }

    /** Anzahl Findings je Tag (neu entstanden) der letzten 14 Tage. @return array<string,int> */
    public static function findingsPerDay(int $days = 14): array
    {
        $out = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $out[gmdate('Y-m-d', time() - $i * 86400)] = 0;
        }
        foreach (Database::all('SELECT DATE(first_seen) d, COUNT(*) c FROM findings WHERE first_seen >= ? GROUP BY DATE(first_seen)', [gmdate('Y-m-d', time() - $days * 86400)]) as $r) {
            if (isset($out[$r['d']])) {
                $out[$r['d']] = (int) $r['c'];
            }
        }
        return $out;
    }
}

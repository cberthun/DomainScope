<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;

/** Certificate-Transparency-Zertifikate je Domain; der erste Scan bildet den Ausgangsbestand (Baseline). */
final class CtRepository
{
    /**
     * @param array<int,array{serial:string,issuer:string,ct_id:string,names:string[],not_before:?string,not_after:?string}> $certs
     * @return array{first:bool,new:array<int,array<string,mixed>>,total:int}
     */
    public static function saveScan(int $domainId, array $certs): array
    {
        $now = Database::now();
        return Database::transaction(static function () use ($domainId, $certs, $now): array {
            $first = (int) Database::value('SELECT COUNT(*) FROM ct_certificates WHERE domain_id = ?', [$domainId]) === 0;
            $issuers = [];
            foreach (Database::all('SELECT DISTINCT issuer FROM ct_certificates WHERE domain_id = ?', [$domainId]) as $r) {
                $issuers[strtolower($r['issuer'])] = true;
            }
            // Aussteller der selbst beobachteten TLS-Zertifikate gelten ebenfalls als bekannt
            foreach (Database::all('SELECT DISTINCT c.issuer FROM tls_checks t JOIN certificates c ON c.id = t.certificate_id WHERE t.domain_id = ?', [$domainId]) as $r) {
                $issuers[strtolower(self::cn((string) $r['issuer']))] = true;
            }
            $new = [];
            foreach ($certs as $c) {
                $row = Database::one('SELECT id FROM ct_certificates WHERE domain_id = ? AND serial = ? AND issuer = ?', [$domainId, $c['serial'], $c['issuer']]);
                if ($row) {
                    Database::run('UPDATE ct_certificates SET last_seen = ? WHERE id = ?', [$now, $row['id']]);
                    continue;
                }
                $known = $first || isset($issuers[strtolower($c['issuer'])]);
                Database::insert('ct_certificates', [
                    'domain_id' => $domainId, 'serial' => $c['serial'], 'ct_id' => $c['ct_id'] ?: null, 'issuer' => $c['issuer'],
                    'names' => json_out(array_slice($c['names'], 0, 100)), 'not_before' => $c['not_before'], 'not_after' => $c['not_after'],
                    'first_seen' => $now, 'last_seen' => $now, 'baseline' => (int) $first, 'known_issuer' => (int) $known,
                ]);
                if (!$first) {
                    $new[] = $c + ['known_issuer' => $known];
                }
            }
            return ['first' => $first, 'new' => $new, 'total' => count($certs)];
        });
    }

    /** Neu entdeckte (nicht-Baseline) Zertifikate der letzten $days Tage. @return array<int,array<string,mixed>> */
    public static function recentNew(int $domainId, int $days = 30): array
    {
        $rows = Database::all(
            'SELECT * FROM ct_certificates WHERE domain_id = ? AND baseline = 0 AND first_seen >= ? ORDER BY first_seen DESC',
            [$domainId, gmdate('Y-m-d H:i:s', time() - $days * 86400)]
        );
        return array_map(static fn($r) => $r + ['names_list' => json_decode((string) $r['names'], true) ?: []], $rows);
    }

    /** @return array<int,array<string,mixed>> */
    public static function forDomain(int $domainId, int $limit = 200): array
    {
        $rows = Database::all('SELECT * FROM ct_certificates WHERE domain_id = ? ORDER BY not_before DESC LIMIT ' . (int) $limit, [$domainId]);
        return array_map(static fn($r) => $r + ['names_list' => json_decode((string) $r['names'], true) ?: []], $rows);
    }

    public static function cn(string $dn): string
    {
        return preg_match('/CN=([^,]+)/', $dn, $m) ? trim($m[1]) : $dn;
    }
}

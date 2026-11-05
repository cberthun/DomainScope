<?php
declare(strict_types=1);

namespace DomainScope\Repositories;

use DomainScope\Support\Database;
use DomainScope\Validation\Target;

final class DomainRepository
{
    /** @return array<string,mixed>|null */
    public static function find(string $name): ?array
    {
        return Database::one('SELECT * FROM domains WHERE name = ?', [strtolower($name)]);
    }

    /** @return array<string,mixed>|null */
    public static function findById(int $id): ?array
    {
        return Database::one('SELECT * FROM domains WHERE id = ?', [$id]);
    }

    /** Legt die registrierbare Domain an (falls neu) und liefert die Zeile. @return array<string,mixed> */
    public static function ensure(Target $t): array
    {
        if (!$t->isDomain() || $t->registrable === null) {
            throw new \InvalidArgumentException('Keine registrierbare Domain.');
        }
        $existing = self::find($t->registrable);
        if ($existing !== null) {
            return $existing;
        }
        $unicode = \DomainScope\Validation\DomainName::toUnicode($t->registrable);
        $suffix = \DomainScope\Validation\PublicSuffix::suffix($t->registrable);
        Database::run(
            'INSERT IGNORE INTO domains (name, unicode_name, public_suffix, tld, created_at) VALUES (?,?,?,?,?)',
            [$t->registrable, $unicode, $suffix, \DomainScope\Validation\PublicSuffix::tld($t->registrable), Database::now()]
        );
        ActivityRepository::log('domain', 'Domain ' . $unicode . ' hinzugefügt', (int) self::find($t->registrable)['id']);
        return self::find($t->registrable);
    }

    /** @return array<int,array<string,mixed>> */
    public static function all(string $order = 'name'): array
    {
        $orderBy = match ($order) {
            'checked' => 'd.last_checked_at DESC', 'created' => 'd.created_at DESC', default => 'd.name ASC',
        };
        return Database::all(
            "SELECT d.*,
                (SELECT COUNT(*) FROM subdomains s WHERE s.domain_id = d.id AND s.status = 'present') AS subdomain_count,
                (SELECT COUNT(*) FROM findings f WHERE f.domain_id = d.id AND f.status IN ('open','acknowledged') AND f.severity IN ('critical','high')) AS serious_findings,
                (SELECT COUNT(*) FROM findings f WHERE f.domain_id = d.id AND f.status = 'open') AS open_findings
             FROM domains d ORDER BY $orderBy"
        );
    }

    public static function touch(int $id): void
    {
        Database::run('UPDATE domains SET last_checked_at = ? WHERE id = ?', [Database::now(), $id]);
    }

    public static function setMonitored(int $id, bool $on): void
    {
        Database::run('UPDATE domains SET monitored = ? WHERE id = ?', [(int) $on, $id]);
    }

    public static function setNotes(int $id, string $notes): void
    {
        Database::run('UPDATE domains SET notes = ? WHERE id = ?', [mb_substr($notes, 0, 5000), $id]);
    }

    public static function setSelectors(int $id, string $csv): void
    {
        Database::run('UPDATE domains SET dkim_selectors = ? WHERE id = ?', [mb_substr($csv, 0, 500), $id]);
    }

    public static function delete(int $id): void
    {
        Database::run('DELETE FROM domains WHERE id = ?', [$id]);
    }

    /** @return array<int,array<string,mixed>> */
    public static function monitored(): array
    {
        return Database::all('SELECT * FROM domains WHERE monitored = 1 ORDER BY name');
    }
}

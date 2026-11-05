<?php
declare(strict_types=1);

namespace DomainScope\Tests\Integration;

use DomainScope\Support\{Database, Migrator, Settings};
use PHPUnit\Framework\TestCase;

/** Basis für Tests gegen eine echte MySQL/MariaDB-Testdatenbank (Standard: domainscope_test). */
abstract class DatabaseTestCase extends TestCase
{
    private static bool $ready = false;
    private static ?string $skip = null;

    public static function setUpBeforeClass(): void
    {
        if (self::$ready || self::$skip !== null) {
            return;
        }
        try {
            Database::setConnection(null);
            Database::connection();
            $m = new Migrator();
            $m->dropAll();
            $m->migrate();
            self::$ready = true;
        } catch (\Throwable $e) {
            self::$skip = 'Testdatenbank nicht verfügbar: ' . $e->getMessage();
        }
    }

    protected function setUp(): void
    {
        if (self::$skip !== null) {
            self::markTestSkipped(self::$skip);
        }
        $pdo = Database::connection();
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
        foreach (Database::all('SHOW TABLES') as $row) {
            $t = array_values($row)[0];
            if ($t !== 'schema_migrations') {
                $pdo->exec('TRUNCATE TABLE `' . $t . '`');
            }
        }
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
        Settings::reset();
    }

    /** @return array<string,mixed> */
    protected function domain(string $name = 'example.com'): array
    {
        $t = \DomainScope\Validation\Target::parse($name);
        return \DomainScope\Repositories\DomainRepository::ensure($t);
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Wendet SQL-Migrationen aus database/migrations idempotent an (Tabelle schema_migrations). */
final class Migrator
{
    public function __construct(private readonly ?string $dir = null)
    {
    }

    /** @return array<int,array{version:string,applied:bool}> */
    public function status(): array
    {
        $this->ensureTable();
        $applied = array_column(Database::all('SELECT version FROM schema_migrations'), 'version');
        $out = [];
        foreach ($this->files() as $file) {
            $v = basename($file, '.sql');
            $out[] = ['version' => $v, 'applied' => in_array($v, $applied, true)];
        }
        return $out;
    }

    /**
     * @param callable|null $log fn(string $line)
     * @return int Anzahl angewendeter Migrationen
     */
    public function migrate(?callable $log = null): int
    {
        $this->ensureTable();
        $pdo = Database::connection();
        $applied = array_column(Database::all('SELECT version FROM schema_migrations'), 'version');
        $n = 0;
        foreach ($this->files() as $file) {
            $version = basename($file, '.sql');
            if (in_array($version, $applied, true)) {
                $log && $log("  [ok]      $version");
                continue;
            }
            $log && $log("  [apply]   $version");
            $statements = preg_split('/;\s*(?:\r?\n|$)/', (string) file_get_contents($file)) ?: [];
            foreach ($statements as $stmt) {
                $stmt = trim(preg_replace('/^\s*--.*$/m', '', $stmt) ?? '');
                if ($stmt !== '') {
                    $pdo->exec($stmt);
                }
            }
            Database::insert('schema_migrations', ['version' => $version, 'applied_at' => Database::now()]);
            $n++;
        }
        return $n;
    }

    /** Entfernt alle Tabellen (nur für Tests). */
    public function dropAll(): void
    {
        $pdo = Database::connection();
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
        foreach (Database::all('SHOW TABLES') as $row) {
            $pdo->exec('DROP TABLE IF EXISTS `' . array_values($row)[0] . '`');
        }
        $pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
    }

    private function ensureTable(): void
    {
        Database::connection()->exec('CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(100) NOT NULL PRIMARY KEY,
            applied_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    }

    /** @return string[] */
    private function files(): array
    {
        $dir = $this->dir ?? dirname(__DIR__, 2) . '/database/migrations';
        $files = glob($dir . '/*.sql') ?: [];
        sort($files);
        return $files;
    }
}

<?php
declare(strict_types=1);

/**
 * Führt SQL-Migrationen aus database/migrations aus (idempotent).
 * Aufruf:  php bin/migrate.php [--status]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/app/bootstrap.php';

use DomainScope\Support\Migrator;

$migrator = new Migrator();
try {
    if (in_array('--status', $argv, true)) {
        $pending = 0;
        foreach ($migrator->status() as $m) {
            echo ($m['applied'] ? '  [ok]      ' : '  [pending] ') . $m['version'] . "\n";
            $pending += $m['applied'] ? 0 : 1;
        }
        echo $pending ? "$pending Migration(en) ausstehend.\n" : "Datenbank ist aktuell.\n";
        exit(0);
    }
    $n = $migrator->migrate(static function (string $l): void {
        echo $l . "\n";
    });
    echo $n === 0 ? "Datenbank ist aktuell.\n" : "$n Migration(en) angewendet.\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'Migration fehlgeschlagen: ' . $e->getMessage() . "\n");
    exit(1);
}

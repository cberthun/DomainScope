<?php
declare(strict_types=1);

/**
 * Selbsttest für Installation und Update (nur CLI). Exit-Code 0 = gesund, 1 = Fehler.
 * Aufruf:  php bin/health.php [--quiet]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/app/bootstrap.php';

use DomainScope\Support\{Config, Database, Migrator};

$quiet = in_array('--quiet', $argv, true);
$failed = 0;
$check = static function (string $name, callable $fn) use (&$failed, $quiet): void {
    try {
        $detail = $fn();
        if (!$quiet) {
            echo "  [ok]   $name" . ($detail ? " – $detail" : '') . "\n";
        }
    } catch (Throwable $e) {
        $failed++;
        echo "  [FAIL] $name – " . $e->getMessage() . "\n";
    }
};
$need = static function (bool $cond, string $msg): void {
    if (!$cond) {
        throw new RuntimeException($msg);
    }
};

$version = trim((string) @file_get_contents(dirname(__DIR__) . '/VERSION'));
if (!$quiet) {
    echo "DomainScope " . ($version ?: 'unbekannte Version') . "\n";
}

$check('PHP-Version', static function () use ($need): string {
    $need(PHP_VERSION_ID >= 80400, 'PHP 8.4 oder neuer erforderlich (gefunden: ' . PHP_VERSION . ')');
    return PHP_VERSION;
});
$check('PHP-Erweiterungen', static function () use ($need): string {
    foreach (['curl', 'openssl', 'pdo_mysql', 'mbstring', 'json'] as $ext) {
        $need(extension_loaded($ext), "Erweiterung $ext fehlt");
    }
    return '';
});
$check('Konfiguration', static function () use ($need): string {
    $need((string) Config::get('app.key') !== '', 'APP_KEY fehlt (php bin/setup.php)');
    return '';
});
$check('Datenbank', static function (): string {
    Database::connection()->query('SELECT 1');
    return '';
});
$check('Migrationen', static function () use ($need): string {
    $pending = array_filter((new Migrator())->status(), static fn(array $m): bool => !$m['applied']);
    $need($pending === [], count($pending) . ' Migration(en) ausstehend (php bin/migrate.php)');
    return '';
});
$check('Schreibrechte storage/', static function () use ($need): string {
    foreach (['cache', 'logs', 'reports'] as $d) {
        $p = (string) Config::get("app.paths.$d");
        $need(is_dir($p) || @mkdir($p, 0750, true), "$p existiert nicht");
        $need(is_writable($p), "$p ist nicht beschreibbar");
    }
    return '';
});
$check('Datendateien', static function () use ($need): string {
    foreach (['public_suffix_list.dat', 'cacert.pem', 'rdap-dns.json'] as $f) {
        $need(is_file((string) Config::get('app.paths.data') . '/' . $f), "storage/data/$f fehlt");
    }
    return '';
});

exit($failed === 0 ? 0 : 1);

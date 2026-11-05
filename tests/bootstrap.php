<?php
declare(strict_types=1);

/**
 * PHPUnit-Bootstrap: Autoloading, Zeitzone, Testkonfiguration.
 * Datenbanktests verwenden eine eigene Datenbank (TEST_DB_NAME, Standard domainscope_test) –
 * niemals die Produktivdatenbank, da die Tabellen zwischen Tests geleert werden.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use DomainScope\Support\{Config, Env};

Env::load(dirname(__DIR__) . '/.env');
date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');

$testDb = Env::get('TEST_DB_NAME', 'domainscope_test');
Config::override('database', [
    'host' => Env::get('DB_HOST', '127.0.0.1'), 'port' => (int) Env::get('DB_PORT', '3306'), 'name' => $testDb,
    'user' => Env::get('DB_USER', 'root'), 'pass' => Env::get('DB_PASS', ''), 'charset' => 'utf8mb4',
]);

// Unit-Tests arbeiten ohne Cache und ohne externe Netzwerkzugriffe
$app = (array) Config::get('app');
$app['paths']['cache'] = sys_get_temp_dir() . '/domainscope-test-cache';
@mkdir($app['paths']['cache'], 0777, true);
Config::override('app', $app);

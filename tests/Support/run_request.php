<?php
declare(strict_types=1);

/**
 * Führt genau eine HTTP-Anfrage gegen den Anwendungskern in einem eigenen PHP-Prozess aus
 * (echte Session-Behandlung ohne "headers already sent"-Konflikte mit PHPUnit).
 *
 * Eingabe (argv[1]): JSON {method, path, query, post, headers, server, session, config}
 * Ausgabe: JSON {status, headers, body, session}
 */

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use DomainScope\Security\Session;
use DomainScope\Support\{App, Config, Env, Request};

$in = json_decode((string) ($argv[1] ?? '{}'), true) ?: [];
Env::load(dirname(__DIR__, 2) . '/.env');
date_default_timezone_set('UTC');

$dbName = Env::get('TEST_DB_NAME', 'domainscope_test');
Config::override('database', [
    'host' => Env::get('DB_HOST', '127.0.0.1'), 'port' => (int) Env::get('DB_PORT', '3306'), 'name' => $dbName,
    'user' => Env::get('DB_USER', 'root'), 'pass' => Env::get('DB_PASS', ''), 'charset' => 'utf8mb4',
]);
$app = (array) Config::get('app');
$app['paths']['cache'] = sys_get_temp_dir() . '/domainscope-test-cache';
$app['paths']['storage'] = $in['storage'] ?? sys_get_temp_dir() . '/domainscope-test-storage';
@mkdir($app['paths']['storage'] . '/sessions', 0700, true);
foreach (($in['config'] ?? []) as $path => $value) {
    $parts = explode('.', $path);
    $ref = &$app;
    foreach ($parts as $p) {
        $ref = &$ref[$p];
    }
    $ref = $value;
    unset($ref);
}
Config::override('app', $app);

ob_start();
$server = ($in['server'] ?? []) + ['REMOTE_ADDR' => '203.0.113.5', 'REQUEST_URI' => $in['path'] ?? '/', 'REQUEST_METHOD' => $in['method'] ?? 'GET'];
foreach (($in['headers'] ?? []) as $k => $v) {
    $server['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
}
$request = new Request(strtoupper($in['method'] ?? 'GET'), $in['path'] ?? '/', $in['query'] ?? [], $in['post'] ?? [], $server);

// Session vorbereiten (optional Vorbelegung, z. B. angemeldeter Benutzer)
if (!empty($in['session_id'])) {
    session_id($in['session_id']);
}
Session::start($request);
foreach (($in['session'] ?? []) as $k => $v) {
    $_SESSION[$k] = $v;
}
$sid = session_id();

$application = new App();
$response = $application->handle($request);
$flash = $_SESSION['_flash'] ?? [];
$sessionData = $_SESSION;
session_write_close();
ob_end_clean();

echo json_encode([
    'status' => $response->status, 'headers' => $response->headers + $application->securityHeaders($request), 'body' => $response->body,
    'session_id' => $sid, 'session' => $sessionData, 'flash' => $flash,
], JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);

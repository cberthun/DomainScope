<?php
declare(strict_types=1);

/**
 * Gemeinsamer Start für Web, CLI und Tests: Autoloading, .env, Zeitzone, Fehlerbehandlung.
 */

$root = dirname(__DIR__);

if (is_file($root . '/vendor/autoload.php')) {
    require $root . '/vendor/autoload.php';
} else {
    spl_autoload_register(static function (string $class) use ($root): void {
        $prefix = 'DomainScope\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }
        $file = $root . '/app/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });
}
require_once $root . '/app/Support/helpers.php';
require_once $root . '/app/Support/ui.php';

\DomainScope\Support\Env::load($root . '/.env');

date_default_timezone_set((string) \DomainScope\Support\Config::get('app.timezone', 'UTC'));
mb_internal_encoding('UTF-8');

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', $root . '/storage/logs/php-error.log');
error_reporting(E_ALL);

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    if ($severity === E_DEPRECATED || $severity === E_USER_DEPRECATED) {
        error_log("Deprecated: $message in $file:$line");
        return true;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

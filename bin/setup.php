<?php
declare(strict_types=1);

/**
 * Einrichtung: erzeugt .env (falls nötig), APP_KEY und den Passwort-Hash (argon2id/bcrypt).
 * Aufruf:  php bin/setup.php [--user=admin] [--password=...|--password-file=Datei]
 * Ohne --password wird interaktiv gefragt (Eingabe wird auf Unix-Terminals nicht angezeigt).
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$root = dirname(__DIR__);
$envFile = $root . '/.env';
if (!is_file($envFile)) {
    if (!copy($root . '/.env.example', $envFile)) {
        fwrite(STDERR, "Konnte .env nicht anlegen.\n");
        exit(1);
    }
    echo ".env aus .env.example erstellt.\n";
}

$args = [];
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--([a-z-]+)=(.*)$/', $a, $m)) {
        $args[$m[1]] = $m[2];
    }
}

$user = $args['user'] ?? null;
if ($user === null) {
    echo 'Benutzername [admin]: ';
    $user = trim((string) fgets(STDIN)) ?: 'admin';
}
$password = $args['password'] ?? null;
if ($password === null && isset($args['password-file'])) {
    // Passwort aus Datei (erste Zeile): vermeidet das Passwort in der Prozessliste (install.sh)
    $line = is_readable($args['password-file']) ? file($args['password-file'], FILE_IGNORE_NEW_LINES) : false;
    if ($line === false || !isset($line[0])) {
        fwrite(STDERR, "Passwortdatei nicht lesbar oder leer.\n");
        exit(1);
    }
    $password = rtrim($line[0], "\r\n");
}
if ($password === null) {
    $unix = DIRECTORY_SEPARATOR === '/';
    echo 'Neues Passwort (mind. 12 Zeichen): ';
    if ($unix) {
        shell_exec('stty -echo');
    }
    $password = rtrim((string) fgets(STDIN), "\r\n");
    if ($unix) {
        shell_exec('stty echo');
        echo "\n";
    }
}
if (mb_strlen($password) < 12) {
    fwrite(STDERR, "Das Passwort muss mindestens 12 Zeichen lang sein.\n");
    exit(1);
}
$algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
$hash = password_hash($password, $algo);

$env = (string) file_get_contents($envFile);
$set = static function (string $key, string $value) use (&$env): void {
    // $ im Hash wird in .env nicht interpoliert; in einfache Anführungszeichen einschließen
    $line = $key . "='" . $value . "'";
    if (preg_match('/^' . preg_quote($key, '/') . '=.*$/m', $env)) {
        $env = preg_replace('/^' . preg_quote($key, '/') . '=.*$/m', str_replace(['\\', '$'], ['\\\\', '\\$'], $line), $env);
    } else {
        $env .= "\n" . $line . "\n";
    }
};
$set('AUTH_USERNAME', $user);
$set('AUTH_PASSWORD_HASH', $hash);
if (!preg_match('/^APP_KEY=\S+/m', $env)) {
    $set('APP_KEY', bin2hex(random_bytes(32)));
}
file_put_contents($envFile, $env, LOCK_EX);
@chmod($envFile, 0600);
echo "Zugangsdaten gespeichert (Benutzer: $user). Hash-Verfahren: " . ($algo === PASSWORD_ARGON2ID ? 'argon2id' : 'bcrypt') . "\n";

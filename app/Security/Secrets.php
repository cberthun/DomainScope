<?php
declare(strict_types=1);

namespace DomainScope\Security;

use DomainScope\Support\Config;

/** Authentifizierte Verschlüsselung (AES-256-GCM) kleiner Geheimnisse mit einem aus APP_KEY abgeleiteten Schlüssel. */
final class Secrets
{
    private static function key(): string
    {
        $k = (string) Config::get('app.key', '');
        if (strlen($k) < 32) {
            throw new \RuntimeException('APP_KEY fehlt oder ist zu kurz (php bin/setup.php ausführen).');
        }
        return hash('sha256', 'domainscope-secrets|' . $k, true);
    }

    public static function encrypt(string $plain): string
    {
        $iv = random_bytes(12);
        $ct = openssl_encrypt($plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $blob): ?string
    {
        $raw = base64_decode($blob, true);
        if ($raw === false || strlen($raw) < 29) {
            return null;
        }
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
        return $plain === false ? null : $plain;
    }
}

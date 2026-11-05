<?php
declare(strict_types=1);

namespace DomainScope\Security;

use DomainScope\Support\{Config, Database};

/** Zugangsdaten: Datenbankwerte (Passwortwechsel/TOTP in der Oberfläche) überschreiben den Hash aus der .env. */
final class Credentials
{
    private static ?array $row = null;
    private static bool $loaded = false;

    public static function reset(): void
    {
        self::$row = null;
        self::$loaded = false;
    }

    /** @return array<string,mixed>|null */
    public static function row(): ?array
    {
        if (!self::$loaded) {
            self::$loaded = true;
            try {
                self::$row = Database::one('SELECT * FROM auth_credentials WHERE id = 1');
            } catch (\Throwable) {
                self::$row = null;
            }
        }
        return self::$row;
    }

    public static function passwordHash(): string
    {
        return (string) (self::row()['password_hash'] ?? Config::get('app.auth.password_hash', ''));
    }

    public static function totpEnabled(): bool
    {
        $r = self::row();
        return $r !== null && (int) $r['totp_enabled'] === 1 && !empty($r['totp_secret']);
    }

    public static function setPassword(string $plain): void
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        self::save(['password_hash' => password_hash($plain, $algo)]);
    }

    /** @param array<string,mixed> $data */
    public static function save(array $data): void
    {
        $now = Database::now();
        if (Database::one('SELECT id FROM auth_credentials WHERE id = 1') === null) {
            Database::insert('auth_credentials', array_merge(['id' => 1, 'password_hash' => (string) Config::get('app.auth.password_hash', ''), 'updated_at' => $now], $data));
        } else {
            Database::update('auth_credentials', $data + ['updated_at' => $now], 'id = 1');
        }
        self::reset();
    }

    public static function decryptSecret(): ?string
    {
        $r = self::row();
        return $r && $r['totp_secret'] ? Secrets::decrypt((string) $r['totp_secret']) : null;
    }

    /** @return string[] Klartext-Wiederherstellungscodes (nur einmal anzeigen) */
    public static function newRecoveryCodes(): array
    {
        $codes = [];
        $hashes = [];
        for ($i = 0; $i < 8; $i++) {
            $c = bin2hex(random_bytes(5));
            $c = substr($c, 0, 5) . '-' . substr($c, 5);
            $codes[] = $c;
            $hashes[] = hash('sha256', $c);
        }
        self::save(['recovery_codes' => json_encode($hashes)]);
        return $codes;
    }

    public static function useRecoveryCode(string $input): bool
    {
        $input = strtolower(trim($input));
        $hashes = json_decode((string) (self::row()['recovery_codes'] ?? '[]'), true) ?: [];
        $h = hash('sha256', $input);
        foreach ($hashes as $i => $stored) {
            if (hash_equals($stored, $h)) {
                unset($hashes[$i]);
                self::save(['recovery_codes' => json_encode(array_values($hashes))]);
                return true;
            }
        }
        return false;
    }

    public static function recoveryCodesLeft(): int
    {
        return count(json_decode((string) (self::row()['recovery_codes'] ?? '[]'), true) ?: []);
    }
}

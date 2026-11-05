<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Zugriff auf application_settings mit Defaults aus config/app.php. */
final class Settings
{
    /** @var array<string,string>|null */
    private static ?array $cache = null;

    public static function all(): array
    {
        if (self::$cache === null) {
            self::$cache = (array) Config::get('app.defaults', []);
            try {
                foreach (Database::all('SELECT `key`, value FROM application_settings') as $row) {
                    self::$cache[$row['key']] = $row['value'];
                }
            } catch (\Throwable) {
                // Datenbank (noch) nicht verfügbar: Defaults verwenden
            }
        }
        return self::$cache;
    }

    public static function get(string $key, ?string $default = null): string
    {
        return (string) (self::all()[$key] ?? $default ?? '');
    }

    public static function bool(string $key): bool
    {
        return self::get($key) === '1';
    }

    public static function int(string $key): int
    {
        return (int) self::get($key);
    }

    /** @return int[] absteigend sortierte Schwellwerte */
    public static function days(string $key): array
    {
        $vals = array_values(array_unique(array_filter(
            array_map('intval', explode(',', self::get($key))),
            static fn(int $d) => $d > 0
        )));
        rsort($vals);
        return $vals;
    }

    public static function set(string $key, string $value): void
    {
        Database::run(
            'INSERT INTO application_settings (`key`, value, updated_at) VALUES (?,?,?)
             ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = VALUES(updated_at)',
            [$key, $value, Database::now()]
        );
        self::$cache = null;
    }

    public static function reset(): void
    {
        self::$cache = null;
    }
}

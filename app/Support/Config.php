<?php
declare(strict_types=1);

namespace DomainScope\Support;

final class Config
{
    /** @var array<string,array<string,mixed>> */
    private static array $files = [];

    public static function get(string $key, mixed $default = null): mixed
    {
        $parts = explode('.', $key);
        $file = array_shift($parts);
        if (!isset(self::$files[$file])) {
            $path = dirname(__DIR__, 2) . '/config/' . $file . '.php';
            self::$files[$file] = is_file($path) ? (array) require $path : [];
        }
        $value = self::$files[$file];
        foreach ($parts as $p) {
            if (!is_array($value) || !array_key_exists($p, $value)) {
                return $default;
            }
            $value = $value[$p];
        }
        return $value;
    }

    /** Überschreibt eine komplette Konfigurationsdatei (für Tests). */
    public static function override(string $file, array $data): void
    {
        self::$files[$file] = $data;
    }
}

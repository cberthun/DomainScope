<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Einfacher Dateicache mit TTL. Schlüssel werden gehasht (sichere Dateipfade). */
final class Cache
{
    private static function path(string $key): string
    {
        return rtrim((string) Config::get('app.paths.cache'), '/\\') . '/c_' . hash('sha256', $key) . '.cache';
    }

    public static function get(string $key): mixed
    {
        $file = self::path($key);
        if (!is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $data = @unserialize($raw, ['allowed_classes' => false]);
        if (!is_array($data) || !isset($data['exp']) || $data['exp'] < time()) {
            @unlink($file);
            return null;
        }
        return $data['val'];
    }

    public static function set(string $key, mixed $value, int $ttl): void
    {
        $dir = (string) Config::get('app.paths.cache');
        if (!is_dir($dir)) {
            return;
        }
        @file_put_contents(self::path($key), serialize(['exp' => time() + $ttl, 'val' => $value]), LOCK_EX);
    }

    public static function remember(string $key, int $ttl, callable $fn): mixed
    {
        $hit = self::get($key);
        if ($hit !== null) {
            return $hit;
        }
        $value = $fn();
        if ($value !== null) {
            self::set($key, $value, $ttl);
        }
        return $value;
    }

    public static function forget(string $key): void
    {
        @unlink(self::path($key));
    }

    public static function purge(): int
    {
        $n = 0;
        foreach (glob(rtrim((string) Config::get('app.paths.cache'), '/\\') . '/c_*.cache') ?: [] as $f) {
            $n += @unlink($f) ? 1 : 0;
        }
        return $n;
    }
}

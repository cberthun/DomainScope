<?php
declare(strict_types=1);

namespace DomainScope\Validation;

use DomainScope\Support\Config;

/** Public-Suffix-Auswertung auf Basis der offiziellen PSL (ICANN-Bereich). */
final class PublicSuffix
{
    /** @var array{rules:array<string,bool>,wild:array<string,bool>,except:array<string,bool>}|null */
    private static ?array $data = null;
    private static ?string $fileOverride = null;

    public static function useFile(?string $file): void
    {
        self::$fileOverride = $file;
        self::$data = null;
    }

    private static function load(): array
    {
        if (self::$data !== null) {
            return self::$data;
        }
        $src = self::$fileOverride ?? (string) Config::get('app.paths.data') . '/public_suffix_list.dat';
        $cacheFile = (string) Config::get('app.paths.cache') . '/psl_' . substr(md5($src . @filemtime($src)), 0, 12) . '.php';
        if (self::$fileOverride === null && is_file($cacheFile)) {
            $cached = @include $cacheFile;
            if (is_array($cached)) {
                return self::$data = $cached;
            }
        }
        $rules = $wild = $except = [];
        $inIcann = true;
        foreach (@file($src, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $line = trim($line);
            if (str_contains($line, '===BEGIN PRIVATE DOMAINS===')) {
                $inIcann = false;
            }
            if ($line === '' || str_starts_with($line, '//') || !$inIcann) {
                continue;
            }
            $line = trim(explode(' ', $line)[0]);
            $neg = false;
            if (str_starts_with($line, '!')) {
                $neg = true;
                $line = substr($line, 1);
            }
            $isWild = false;
            if (str_starts_with($line, '*.')) {
                $isWild = true;
                $line = substr($line, 2);
            }
            $ascii = Punycode::toAscii(mb_strtolower($line, 'UTF-8'));
            if ($neg) {
                $except[$ascii] = true;
            } elseif ($isWild) {
                $wild[$ascii] = true;
            } else {
                $rules[$ascii] = true;
            }
        }
        $data = ['rules' => $rules, 'wild' => $wild, 'except' => $except];
        if (self::$fileOverride === null && is_dir(dirname($cacheFile))) {
            @file_put_contents($cacheFile, '<?php return ' . var_export($data, true) . ';', LOCK_EX);
        }
        return self::$data = $data;
    }

    /** Liefert den Public Suffix für einen ASCII-Hostnamen. */
    public static function suffix(string $host): string
    {
        $d = self::load();
        $labels = explode('.', $host);
        $n = count($labels);
        $best = 1; // Standardregel "*": TLD ist Suffix
        for ($i = 0; $i < $n; $i++) {
            $cand = implode('.', array_slice($labels, $i));
            $len = $n - $i;
            if (isset($d['except'][$cand])) {
                return implode('.', array_slice($labels, $i + 1));
            }
            if (isset($d['rules'][$cand]) && $len > $best) {
                $best = $len;
            }
            if ($i + 1 < $n) {
                $parent = implode('.', array_slice($labels, $i + 1));
                if (isset($d['wild'][$parent]) && $len > $best) {
                    $best = $len;
                }
            }
        }
        return implode('.', array_slice($labels, $n - min($best, $n)));
    }

    /** Registrierbare Domain (eTLD+1) oder null, wenn der Host selbst ein Public Suffix ist. */
    public static function registrable(string $host): ?string
    {
        $suffix = self::suffix($host);
        if ($host === $suffix) {
            return null;
        }
        $hostLabels = explode('.', $host);
        $sufLabels = substr_count($suffix, '.') + 1;
        return implode('.', array_slice($hostLabels, -($sufLabels + 1)));
    }

    public static function tld(string $host): string
    {
        $labels = explode('.', $host);
        return end($labels);
    }
}

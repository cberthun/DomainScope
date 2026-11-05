<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Protokolliert Erfolg/Fehler externer Datenquellen (Dashboard: Datenquellenstatus). */
final class DataSources
{
    /** @var array<string,array> Sammelpuffer pro Request, wird am Ende persistiert */
    private static array $buffer = [];

    public static function ok(string $name, string $label, int $ms): void
    {
        $b = &self::$buffer[$name];
        $b ??= ['label' => $label, 'ok' => 0, 'fail' => 0, 'ms' => 0, 'error' => null];
        $b['ok']++;
        $b['ms'] += $ms;
    }

    public static function fail(string $name, string $label, string $error, int $ms = 0): void
    {
        $b = &self::$buffer[$name];
        $b ??= ['label' => $label, 'ok' => 0, 'fail' => 0, 'ms' => 0, 'error' => null];
        $b['fail']++;
        $b['error'] = mb_substr(Logger::scrub($error), 0, 450);
        $b['ms'] += $ms;
    }

    /** Schreibt den Puffer in die Datenbank (best effort). */
    public static function flush(): void
    {
        if (self::$buffer === []) {
            return;
        }
        $buf = self::$buffer;
        self::$buffer = [];
        try {
            $now = Database::now();
            foreach ($buf as $name => $b) {
                $calls = $b['ok'] + $b['fail'];
                $avg = $calls > 0 ? (int) round($b['ms'] / $calls) : null;
                Database::run(
                    'INSERT INTO data_source_status (name, label, last_ok_at, last_error_at, last_error, ok_count, fail_count, avg_ms)
                     VALUES (?,?,?,?,?,?,?,?)
                     ON DUPLICATE KEY UPDATE
                        label = VALUES(label),
                        last_ok_at = IF(VALUES(ok_count) > 0, VALUES(last_ok_at), last_ok_at),
                        last_error_at = IF(VALUES(fail_count) > 0, VALUES(last_error_at), last_error_at),
                        last_error = IF(VALUES(fail_count) > 0, VALUES(last_error), last_error),
                        ok_count = ok_count + VALUES(ok_count),
                        fail_count = fail_count + VALUES(fail_count),
                        avg_ms = IF(avg_ms IS NULL, VALUES(avg_ms), ROUND((avg_ms + VALUES(avg_ms)) / 2))',
                    [
                        $name, $b['label'], $b['ok'] > 0 ? $now : null, $b['fail'] > 0 ? $now : null,
                        $b['error'], $b['ok'], $b['fail'], $avg,
                    ]
                );
            }
        } catch (\Throwable $e) {
            Logger::warning('Datenquellenstatus konnte nicht gespeichert werden: ' . $e->getMessage());
        }
    }

    public static function reset(): void
    {
        self::$buffer = [];
    }
}

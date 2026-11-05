<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Dateibasiertes Logging; maskiert offensichtliche Geheimnisse. */
final class Logger
{
    public static function log(string $level, string $message, array $context = []): void
    {
        $dir = (string) Config::get('app.paths.logs');
        if (!is_dir($dir)) {
            return;
        }
        $line = sprintf(
            "[%s] %s: %s%s\n",
            date('c'),
            strtoupper($level),
            self::scrub($message),
            $context ? ' ' . self::scrub(json_encode($context, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR) ?: '') : ''
        );
        @file_put_contents($dir . '/app-' . date('Y-m-d') . '.log', $line, FILE_APPEND | LOCK_EX);
    }

    public static function error(string $message, array $context = []): void
    {
        self::log('error', $message, $context);
    }

    public static function warning(string $message, array $context = []): void
    {
        self::log('warning', $message, $context);
    }

    public static function info(string $message, array $context = []): void
    {
        self::log('info', $message, $context);
    }

    public static function exception(\Throwable $e): void
    {
        self::error(get_class($e) . ': ' . $e->getMessage(), ['file' => basename($e->getFile()), 'line' => $e->getLine()]);
    }

    public static function scrub(string $text): string
    {
        $text = preg_replace('/(password|passwd|pass|secret|token|api[_-]?key|authorization)(["\']?\s*[:=]\s*["\']?)(?:(?:bearer|basic)\s+)?[^\s"\',&]+/i', '$1$2***', $text) ?? $text;
        return str_replace(["\r", "\n"], ' ', $text);
    }
}

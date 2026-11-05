<?php
declare(strict_types=1);

use DomainScope\Support\Config;
use DomainScope\Support\Icons;

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function cfg(string $key, mixed $default = null): mixed
{
    return Config::get($key, $default);
}

function icon(string $name, string $class = ''): string
{
    return Icons::svg($name, $class);
}

function url(string $path = '', array $query = []): string
{
    $path = '/' . ltrim($path, '/');
    $q = array_filter($query, static fn($v) => $v !== null && $v !== '');
    return $path . ($q ? '?' . http_build_query($q) : '');
}

/** Datenbankzeitstempel sind UTC; Strings ohne Zeitzone werden als UTC interpretiert. */
function ds_datetime(string $dt): DateTimeImmutable
{
    return new DateTimeImmutable($dt, new DateTimeZone('UTC'));
}

function fmt_dt(?string $dt, string $format = 'd.m.Y H:i'): string
{
    if ($dt === null || $dt === '') {
        return '–';
    }
    try {
        return ds_datetime($dt)->setTimezone(new DateTimeZone(date_default_timezone_get()))->format($format);
    } catch (Throwable) {
        return (string) $dt;
    }
}

function time_ago(?string $dt): string
{
    if (!$dt) {
        return 'nie';
    }
    try {
        $diff = time() - ds_datetime($dt)->getTimestamp();
    } catch (Throwable) {
        return '–';
    }
    if ($diff < 0) {
        return 'in der Zukunft';
    }
    return match (true) {
        $diff < 60 => 'gerade eben',
        $diff < 3600 => 'vor ' . intdiv($diff, 60) . ' Min.',
        $diff < 86400 => 'vor ' . intdiv($diff, 3600) . ' Std.',
        default => 'vor ' . intdiv($diff, 86400) . ' Tg.',
    };
}

function days_until(?string $dt): ?int
{
    if (!$dt) {
        return null;
    }
    try {
        $ts = ds_datetime($dt)->getTimestamp();
    } catch (Throwable) {
        return null;
    }
    return (int) floor(($ts - time()) / 86400);
}

function severity_label(string $s): string
{
    return match ($s) {
        'critical' => 'Kritisch', 'high' => 'Hoch', 'medium' => 'Mittel', 'low' => 'Niedrig',
        'info' => 'Information', default => 'Unbekannt',
    };
}

function badge(string $text, string $kind = 'neutral'): string
{
    return '<span class="badge badge-' . e($kind) . '">' . e($text) . '</span>';
}

function sev_badge(string $s): string
{
    return '<span class="badge sev-' . e($s) . '">' . e(severity_label($s)) . '</span>';
}

/** Kopierbarer technischer Wert (Klick kopiert in die Zwischenablage). */
function copyable(mixed $value, ?string $display = null): string
{
    $v = (string) $value;
    return '<span class="copyable mono" data-copy="' . e($v) . '" title="Klicken zum Kopieren">' . e($display ?? $v) . '</span>';
}

function json_out(mixed $data, int $flags = 0): string
{
    return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | $flags) ?: 'null';
}

/** Kürzel der Anzeige-Zeitzone (z. B. CET/CEST) – Zeitstempel werden in der konfigurierten Ortszeit angezeigt. */
function tz_label(): string
{
    return date('T');
}

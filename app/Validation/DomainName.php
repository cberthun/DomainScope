<?php
declare(strict_types=1);

namespace DomainScope\Validation;

/** Normalisierung und Validierung von Domainnamen (IDN/Punycode). */
final class DomainName
{
    /**
     * Normalisiert einen Hostnamen zur ASCII-Form. Gibt null zurück, wenn er ungültig ist.
     *
     * @param bool $allowUnderscore erlaubt führende Unterstriche in Labels (z. B. _dmarc, _domainkey)
     */
    public static function normalize(string $input, bool $allowUnderscore = false): ?string
    {
        $host = trim($input);
        if ($host === '' || preg_match('/[\x00-\x20\x7F\/\\\\@?#:%]/', $host)) {
            return null;
        }
        // ideographische Punkte und Fullwidth-Punkt als Trenner
        $host = str_replace(["\u{3002}", "\u{FF0E}", "\u{FF61}"], '.', $host);
        $host = rtrim($host, '.');
        if ($host === '' || str_contains($host, '..') || str_starts_with($host, '.')) {
            return null;
        }
        if (class_exists(\Normalizer::class)) {
            $host = \Normalizer::normalize($host, \Normalizer::FORM_C) ?: $host;
        }
        $host = mb_strtolower($host, 'UTF-8');
        try {
            $ascii = Punycode::toAscii($host);
        } catch (\Throwable) {
            return null;
        }
        if (strlen($ascii) > 253) {
            return null;
        }
        $labels = explode('.', $ascii);
        foreach ($labels as $i => $label) {
            $len = strlen($label);
            if ($len < 1 || $len > 63) {
                return null;
            }
            if (str_starts_with($label, '-') || str_ends_with($label, '-')) {
                return null;
            }
            $pattern = $allowUnderscore ? '/^[a-z0-9_-]+$/' : '/^[a-z0-9-]+$/';
            if (!preg_match($pattern, $label)) {
                return null;
            }
            if (!$allowUnderscore && str_contains($label, '_')) {
                return null;
            }
            // xn--Labels müssen dekodierbar sein
            if (str_starts_with($label, 'xn--')) {
                try {
                    if (Punycode::decode(substr($label, 4)) === '') {
                        return null;
                    }
                } catch (\Throwable) {
                    return null;
                }
            }
        }
        // TLD darf nicht rein numerisch sein (Abgrenzung zu IP-Adressen)
        if (preg_match('/^\d+$/', end($labels))) {
            return null;
        }
        return $ascii;
    }

    public static function toUnicode(string $ascii): string
    {
        return Punycode::toUnicode($ascii);
    }

    public static function isValid(string $input): bool
    {
        return self::normalize($input) !== null;
    }
}

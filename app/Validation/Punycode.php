<?php
declare(strict_types=1);

namespace DomainScope\Validation;

/** Punycode nach RFC 3492 (ohne intl-Erweiterung). */
final class Punycode
{
    private const BASE = 36;
    private const TMIN = 1;
    private const TMAX = 26;
    private const SKEW = 38;
    private const DAMP = 700;
    private const INITIAL_BIAS = 72;
    private const INITIAL_N = 128;

    public static function encode(string $input): string
    {
        $cps = self::codepoints($input);
        $n = self::INITIAL_N;
        $delta = 0;
        $bias = self::INITIAL_BIAS;
        $out = '';
        foreach ($cps as $c) {
            if ($c < 128) {
                $out .= chr($c);
            }
        }
        $b = strlen($out);
        $h = $b;
        if ($b > 0) {
            $out .= '-';
        }
        $total = count($cps);
        while ($h < $total) {
            $m = PHP_INT_MAX;
            foreach ($cps as $c) {
                if ($c >= $n && $c < $m) {
                    $m = $c;
                }
            }
            $delta += ($m - $n) * ($h + 1);
            $n = $m;
            foreach ($cps as $c) {
                if ($c < $n) {
                    $delta++;
                }
                if ($c === $n) {
                    $q = $delta;
                    for ($k = self::BASE;; $k += self::BASE) {
                        $t = $k <= $bias ? self::TMIN : ($k >= $bias + self::TMAX ? self::TMAX : $k - $bias);
                        if ($q < $t) {
                            break;
                        }
                        $out .= self::digit($t + (($q - $t) % (self::BASE - $t)));
                        $q = intdiv($q - $t, self::BASE - $t);
                    }
                    $out .= self::digit($q);
                    $bias = self::adapt($delta, $h + 1, $h === $b);
                    $delta = 0;
                    $h++;
                }
            }
            $delta++;
            $n++;
        }
        return $out;
    }

    public static function decode(string $input): string
    {
        $n = self::INITIAL_N;
        $i = 0;
        $bias = self::INITIAL_BIAS;
        $pos = strrpos($input, '-');
        $out = [];
        if ($pos !== false) {
            foreach (str_split(substr($input, 0, $pos)) as $ch) {
                $out[] = ord($ch);
            }
            $pos++;
        } else {
            $pos = 0;
        }
        $len = strlen($input);
        while ($pos < $len) {
            $oldi = $i;
            $w = 1;
            for ($k = self::BASE;; $k += self::BASE) {
                if ($pos >= $len) {
                    throw new \InvalidArgumentException('Ungültiges Punycode');
                }
                $digit = self::digitValue($input[$pos++]);
                $i += $digit * $w;
                $t = $k <= $bias ? self::TMIN : ($k >= $bias + self::TMAX ? self::TMAX : $k - $bias);
                if ($digit < $t) {
                    break;
                }
                $w *= (self::BASE - $t);
            }
            $count = count($out) + 1;
            $bias = self::adapt($i - $oldi, $count, $oldi === 0);
            $n += intdiv($i, $count);
            $i %= $count;
            array_splice($out, $i, 0, [$n]);
            $i++;
        }
        return implode('', array_map(static fn(int $cp) => mb_chr($cp, 'UTF-8'), $out));
    }

    /** Wandelt einen vollständigen Hostnamen nach ASCII (xn--). */
    public static function toAscii(string $host): string
    {
        $labels = explode('.', $host);
        foreach ($labels as &$label) {
            if (preg_match('/[^\x00-\x7F]/', $label)) {
                $label = 'xn--' . self::encode($label);
            }
        }
        return implode('.', $labels);
    }

    public static function toUnicode(string $host): string
    {
        $labels = explode('.', $host);
        foreach ($labels as &$label) {
            if (str_starts_with(strtolower($label), 'xn--')) {
                try {
                    $label = self::decode(substr($label, 4));
                } catch (\Throwable) {
                    // ungültiges Label unverändert lassen
                }
            }
        }
        return implode('.', $labels);
    }

    /** @return int[] */
    private static function codepoints(string $s): array
    {
        $out = [];
        foreach (mb_str_split($s, 1, 'UTF-8') as $ch) {
            $out[] = mb_ord($ch, 'UTF-8');
        }
        return $out;
    }

    private static function adapt(int $delta, int $numPoints, bool $first): int
    {
        $delta = $first ? intdiv($delta, self::DAMP) : intdiv($delta, 2);
        $delta += intdiv($delta, $numPoints);
        $k = 0;
        while ($delta > intdiv((self::BASE - self::TMIN) * self::TMAX, 2)) {
            $delta = intdiv($delta, self::BASE - self::TMIN);
            $k += self::BASE;
        }
        return $k + intdiv((self::BASE - self::TMIN + 1) * $delta, $delta + self::SKEW);
    }

    private static function digit(int $d): string
    {
        return chr($d < 26 ? $d + 97 : $d + 22);
    }

    private static function digitValue(string $c): int
    {
        $o = ord($c);
        return match (true) {
            $o >= 48 && $o <= 57 => $o - 22,
            $o >= 65 && $o <= 90 => $o - 65,
            $o >= 97 && $o <= 122 => $o - 97,
            default => throw new \InvalidArgumentException('Ungültiges Punycode-Zeichen'),
        };
    }
}

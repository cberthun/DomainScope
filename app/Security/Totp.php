<?php
declare(strict_types=1);

namespace DomainScope\Security;

/** TOTP nach RFC 6238 (HMAC-SHA1, 30 s, 6 Stellen) und Base32 nach RFC 4648. */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    public static function base32Encode(string $bin): string
    {
        $bits = '';
        foreach (str_split($bin) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function base32Decode(string $s): string
    {
        $s = strtoupper(preg_replace('/[\s=-]+/', '', $s) ?? '');
        $bits = '';
        foreach (str_split($s) as $c) {
            $p = strpos(self::ALPHABET, $c);
            if ($p === false) {
                return '';
            }
            $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }

    public static function code(string $secretBase32, int $counter, int $digits = 6): string
    {
        $key = self::base32Decode($secretBase32);
        $hash = hash_hmac('sha1', pack('J', $counter), $key, true);
        $o = ord($hash[19]) & 0xF;
        $n = ((ord($hash[$o]) & 0x7F) << 24) | (ord($hash[$o + 1]) << 16) | (ord($hash[$o + 2]) << 8) | ord($hash[$o + 3]);
        return str_pad((string) ($n % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Prüft einen Code (Toleranz ±1 Zeitfenster). Liefert den verwendeten Zähler oder null.
     * $lastCounter verhindert die Wiederverwendung eines Codes (Replay).
     */
    public static function verify(string $secretBase32, string $input, int $lastCounter = 0, ?int $now = null, int $window = 1): ?int
    {
        $input = preg_replace('/\s+/', '', $input) ?? '';
        if (!preg_match('/^\d{6}$/', $input) || self::base32Decode($secretBase32) === '') {
            return null;
        }
        $current = intdiv($now ?? time(), 30);
        for ($i = -$window; $i <= $window; $i++) {
            $c = $current + $i;
            if ($c > $lastCounter && hash_equals(self::code($secretBase32, $c), $input)) {
                return $c;
            }
        }
        return null;
    }

    public static function uri(string $secret, string $account, string $issuer = 'DomainScope'): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account) . '?secret=' . $secret . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }
}

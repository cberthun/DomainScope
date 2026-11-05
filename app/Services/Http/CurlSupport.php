<?php
declare(strict_types=1);

namespace DomainScope\Services\Http;

use DomainScope\Support\Config;

/** Gemeinsame cURL-Grundeinstellungen (CA-Bundle, Timeouts, Protokollbeschränkung). */
final class CurlSupport
{
    public static function caBundle(): ?string
    {
        $bundled = (string) Config::get('app.paths.data') . '/cacert.pem';
        if (is_file($bundled)) {
            return $bundled;
        }
        $ini = (string) ini_get('curl.cainfo');
        if ($ini !== '' && is_file($ini)) {
            return $ini;
        }
        return null;
    }

    /** @return array<int,mixed> */
    public static function baseOptions(int $timeout, int $connectTimeout, int $protocols = CURLPROTO_HTTPS): array
    {
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $connectTimeout,
            CURLOPT_PROTOCOLS => $protocols,
            CURLOPT_REDIR_PROTOCOLS => $protocols,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => (string) Config::get('app.http.user_agent'),
            CURLOPT_ENCODING => '',
            CURLOPT_NOSIGNAL => true,
        ];
        $ca = self::caBundle();
        if ($ca !== null) {
            $opts[CURLOPT_CAINFO] = $ca;
        }
        return $opts;
    }

    public static function caFile(): ?string
    {
        return self::caBundle();
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Services\Http;

use DomainScope\Support\Config;
use DomainScope\Support\DataSources;
use DomainScope\Validation\DomainName;
use DomainScope\Validation\IpClassifier;

/**
 * HTTP-Client mit SSRF-Schutz:
 *  - nur http/https, nur erlaubte Ports, keine Zugangsdaten in der URL
 *  - Zieladresse wird aufgelöst, auf öffentliche IPs geprüft und per CURLOPT_RESOLVE gepinnt (DNS-Rebinding)
 *  - Redirects werden manuell verfolgt und bei jedem Hop erneut geprüft
 *  - Antwortgröße und Zeit sind begrenzt
 */
final class SafeHttp
{
    /** @var callable|null fn(array $hop): array Testweiche statt echtem cURL-Aufruf */
    public static $transport = null;

    /**
     * @param array{method?:string,headers?:string[],max_bytes?:int,timeout?:int,max_redirects?:int,follow?:bool,source?:string,label?:string} $opts
     * @return array{ok:bool,status:int,headers:array<string,string>,body:string,final_url:string,ip:?string,redirects:array,ms:int,error:?string,error_code:?string,truncated:bool}
     */
    public static function request(string $url, array $opts = []): array
    {
        $method = strtoupper($opts['method'] ?? 'GET');
        $maxRedirects = $opts['max_redirects'] ?? (int) Config::get('app.http.max_redirects', 5);
        $follow = $opts['follow'] ?? true;
        $chain = [];
        $current = $url;
        $started = microtime(true);
        $last = null;

        for ($hop = 0; $hop <= $maxRedirects; $hop++) {
            $check = self::validateUrl($current);
            if (!$check['ok']) {
                return self::fail($chain, $current, $started, 'blocked', $check['reason']);
            }
            $res = self::hop($check, $method, $opts);
            $last = $res;
            $chain[] = ['url' => $current, 'status' => $res['status'], 'ip' => $check['ip']];
            if (!$res['ok'] && $res['status'] === 0) {
                return $res + ['redirects' => $chain, 'final_url' => $current, 'ms' => self::ms($started)];
            }
            if ($follow && in_array($res['status'], [301, 302, 303, 307, 308], true) && isset($res['headers']['location'])) {
                $next = self::resolveLocation($current, $res['headers']['location']);
                if ($next === null) {
                    return self::fail($chain, $current, $started, 'blocked', 'Ungültiges Redirect-Ziel.');
                }
                $current = $next;
                if ($res['status'] === 303 || (in_array($res['status'], [301, 302], true) && $method === 'POST')) {
                    $method = 'GET';
                }
                continue;
            }
            return $res + ['redirects' => $chain, 'final_url' => $current, 'ms' => self::ms($started)];
        }
        return self::fail($chain, $current, $started, 'redirects', 'Zu viele Weiterleitungen (max. ' . $maxRedirects . ').');
    }

    /** @return array{ok:bool,reason:?string,scheme?:string,host?:string,port?:int,ip?:?string,url?:string} */
    public static function validateUrl(string $url): array
    {
        if (strlen($url) > 2048 || preg_match('/[\x00-\x20\x7F]/', $url)) {
            return ['ok' => false, 'reason' => 'Ungültige URL.'];
        }
        $p = parse_url($url);
        if ($p === false || empty($p['scheme']) || empty($p['host'])) {
            return ['ok' => false, 'reason' => 'Ungültige URL.'];
        }
        $scheme = strtolower($p['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return ['ok' => false, 'reason' => 'Nur http/https sind erlaubt.'];
        }
        if (isset($p['user']) || isset($p['pass'])) {
            return ['ok' => false, 'reason' => 'Zugangsdaten in URLs sind nicht erlaubt.'];
        }
        $host = trim($p['host'], '[]');
        $port = $p['port'] ?? ($scheme === 'https' ? 443 : 80);
        if (!in_array($port, (array) Config::get('app.http.allowed_ports', [80, 443]), true)) {
            return ['ok' => false, 'reason' => "Port $port ist nicht erlaubt."];
        }
        if (!IpClassifier::isValid($host)) {
            $ascii = DomainName::normalize($host, true);
            if ($ascii === null) {
                return ['ok' => false, 'reason' => 'Ungültiger Hostname.'];
            }
            $host = $ascii;
        }
        $safe = HostResolver::resolveSafe($host);
        if (!$safe['ok']) {
            return ['ok' => false, 'reason' => $safe['reason']];
        }
        return ['ok' => true, 'reason' => null, 'scheme' => $scheme, 'host' => $host, 'port' => (int) $port, 'ip' => $safe['ip'], 'url' => $url];
    }

    private static function resolveLocation(string $base, string $location): ?string
    {
        $location = trim($location);
        if ($location === '' || preg_match('/[\x00-\x1F\x7F]/', $location)) {
            return null;
        }
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location)) {
            return $location;
        }
        $b = parse_url($base);
        if ($b === false || !isset($b['scheme'], $b['host'])) {
            return null;
        }
        $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($location, '//')) {
            return $b['scheme'] . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }
        $dir = preg_replace('#/[^/]*$#', '/', $b['path'] ?? '/') ?: '/';
        return $origin . $dir . $location;
    }

    private static function hop(array $target, string $method, array $opts): array
    {
        $maxBytes = $opts['max_bytes'] ?? (int) Config::get('app.http.max_bytes', 2097152);
        $timeout = $opts['timeout'] ?? (int) Config::get('app.http.timeout', 12);
        $source = $opts['source'] ?? 'http:' . $target['host'];
        $label = $opts['label'] ?? 'HTTP: ' . $target['host'];

        if (self::$transport !== null) {
            return (self::$transport)($target + ['method' => $method, 'opts' => $opts]);
        }

        $headers = [];
        $body = '';
        $truncated = false;
        $ch = curl_init($target['url']);
        $ip = $target['ip'];
        $resolveIp = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $protocols = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        $curlOpts = CurlSupport::baseOptions($timeout, (int) Config::get('app.http.connect_timeout', 5), $protocols) + [
            CURLOPT_RESOLVE => [$target['host'] . ':' . $target['port'] . ':' . $resolveIp],
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HTTPHEADER => array_merge(['Accept: */*'], $opts['headers'] ?? []),
            CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$headers): int {
                $len = strlen($line);
                if (str_contains($line, ':')) {
                    [$k, $v] = explode(':', $line, 2);
                    $k = strtolower(trim($k));
                    $v = trim($v);
                    $headers[$k] = isset($headers[$k]) ? $headers[$k] . ', ' . $v : $v;
                } elseif (str_starts_with($line, 'HTTP/')) {
                    $headers = [];
                }
                return $len;
            },
            CURLOPT_WRITEFUNCTION => static function ($c, string $data) use (&$body, &$truncated, $maxBytes): int {
                if (strlen($body) + strlen($data) > $maxBytes) {
                    $body .= substr($data, 0, max(0, $maxBytes - strlen($body)));
                    $truncated = true;
                    return 0; // Abbruch → Größenlimit erreicht
                }
                $body .= $data;
                return strlen($data);
            },
        ];
        if ($method === 'HEAD') {
            $curlOpts[CURLOPT_NOBODY] = true;
        } elseif ($method !== 'GET') {
            $curlOpts[CURLOPT_CUSTOMREQUEST] = $method;
        }
        curl_setopt_array($ch, $curlOpts);
        curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms = (int) round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);

        if ($truncated) {
            $errno = 0;
        }
        if ($errno !== 0) {
            $code = match (true) {
                $errno === CURLE_OPERATION_TIMEOUTED => 'timeout',
                in_array($errno, [CURLE_SSL_CONNECT_ERROR, CURLE_PEER_FAILED_VERIFICATION, 58, 60, 51, 83], true) => 'tls',
                in_array($errno, [CURLE_COULDNT_CONNECT, CURLE_COULDNT_RESOLVE_HOST], true) => 'connect',
                default => 'error',
            };
            DataSources::fail($source, $label, $error, $ms);
            return [
                'ok' => false, 'status' => 0, 'headers' => $headers, 'body' => '', 'final_url' => $target['url'], 'ip' => $ip,
                'redirects' => [], 'ms' => $ms, 'error' => $error, 'error_code' => $code, 'truncated' => false,
            ];
        }
        DataSources::ok($source, $label, $ms);
        return [
            'ok' => $status >= 200 && $status < 400, 'status' => $status, 'headers' => $headers, 'body' => $body,
            'final_url' => $target['url'], 'ip' => $ip, 'redirects' => [], 'ms' => $ms, 'error' => null,
            'error_code' => null, 'truncated' => $truncated,
        ];
    }

    private static function fail(array $chain, string $url, float $started, string $code, string $message): array
    {
        return [
            'ok' => false, 'status' => 0, 'headers' => [], 'body' => '', 'final_url' => $url, 'ip' => null,
            'redirects' => $chain, 'ms' => self::ms($started), 'error' => $message, 'error_code' => $code, 'truncated' => false,
        ];
    }

    private static function ms(float $started): int
    {
        return (int) round((microtime(true) - $started) * 1000);
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Services\Http;

/** Prüft HTTP-/HTTPS-Erreichbarkeit, Weiterleitungsketten und grundlegende Sicherheits-Header eines Hosts. */
final class HttpCheckService
{
    private const HEADERS = [
        'strict-transport-security' => 'HSTS', 'content-security-policy' => 'CSP', 'x-content-type-options' => 'X-Content-Type-Options',
        'x-frame-options' => 'X-Frame-Options', 'referrer-policy' => 'Referrer-Policy', 'permissions-policy' => 'Permissions-Policy',
    ];

    /** @return array<string,mixed> */
    public function check(string $host): array
    {
        $https = $this->probe("https://$host/");
        $http = $this->probe("http://$host/");
        $hsts = $https['headers']['strict-transport-security'] ?? null;
        $final = $https['final_url'] ?? null;
        $httpToHttps = null;
        if ($http['reachable']) {
            $httpToHttps = $http['final_url'] !== null && str_starts_with($http['final_url'], 'https://');
        }
        $sec = [];
        foreach (self::HEADERS as $h => $label) {
            $sec[] = ['header' => $label, 'present' => isset($https['headers'][$h]), 'value' => isset($https['headers'][$h]) ? mb_substr($https['headers'][$h], 0, 200) : null];
        }
        return [
            'host' => $host, 'https' => $https, 'http' => $http,
            'http_redirects_to_https' => $httpToHttps,
            'hsts' => $hsts, 'hsts_max_age' => $hsts && preg_match('/max-age=(\d+)/i', $hsts, $m) ? (int) $m[1] : null,
            'security_headers' => $sec,
            'server' => $https['headers']['server'] ?? ($http['headers']['server'] ?? null),
            'final_url' => $final, 'checked_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    /** @return array<string,mixed> */
    private function probe(string $url): array
    {
        $r = SafeHttp::request($url, ['max_bytes' => 65536, 'timeout' => 10, 'source' => 'http-check', 'label' => 'HTTP-Erreichbarkeitsprüfung']);
        $tlsProblem = $r['error_code'] === 'tls';
        return [
            'url' => $url, 'reachable' => $r['status'] > 0, 'status' => $r['status'], 'final_url' => $r['final_url'],
            'redirects' => array_map(static fn($h) => ['url' => $h['url'], 'status' => $h['status']], $r['redirects']),
            'ms' => $r['ms'], 'ip' => $r['ip'], 'headers' => array_intersect_key($r['headers'], array_flip(['server', 'location', 'content-type', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy', 'x-powered-by'])),
            'error' => $r['error'], 'error_code' => $r['error_code'], 'tls_problem' => $tlsProblem,
            'title' => $r['status'] > 0 && preg_match('#<title[^>]*>(.*?)</title>#is', $r['body'], $m) ? mb_substr(trim(html_entity_decode(strip_tags($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8')), 0, 160) : null,
        ];
    }
}

<?php
declare(strict_types=1);

use DomainScope\Support\Env;

return [
    'name' => 'DomainScope',
    'env' => Env::get('APP_ENV', 'production'),
    'debug' => Env::bool('APP_DEBUG', false),
    'url' => Env::get('APP_URL', ''),
    'timezone' => Env::get('APP_TIMEZONE', 'Europe/Berlin'),
    'key' => Env::get('APP_KEY', ''),
    'force_https' => Env::bool('FORCE_HTTPS', false),
    'trusted_proxy' => Env::get('TRUSTED_PROXY', ''),
    'auth' => [
        'username' => Env::get('AUTH_USERNAME', 'admin'),
        'password_hash' => Env::get('AUTH_PASSWORD_HASH', ''),
        'ip_allowlist' => array_values(array_filter(array_map('trim', explode(',', (string) Env::get('AUTH_IP_ALLOWLIST', ''))))),
        'idle_timeout' => (int) Env::get('SESSION_IDLE_TIMEOUT', '3600'),
        'max_attempts' => 5,
        'lockout_seconds' => 900,
    ],
    'paths' => [
        'storage' => dirname(__DIR__) . '/storage',
        'cache' => dirname(__DIR__) . '/storage/cache',
        'logs' => dirname(__DIR__) . '/storage/logs',
        'data' => dirname(__DIR__) . '/storage/data',
        'reports' => dirname(__DIR__) . '/storage/reports',
    ],
    'http' => [
        'user_agent' => 'DomainScope/' . trim((string) @file_get_contents(dirname(__DIR__) . '/VERSION'))
            . ' (+https://github.com/cberthun/domainscope' . (Env::get('HTTP_CONTACT', '') !== '' ? '; ' . preg_replace('/[^\x21-\x7e ]/', '', (string) Env::get('HTTP_CONTACT', '')) : '') . ')',
        'connect_timeout' => 5,
        'timeout' => 12,
        'max_bytes' => 2 * 1024 * 1024,
        'max_redirects' => 5,
        'allowed_ports' => [80, 443, 8080, 8443],
    ],
    'dns' => [
        'timeout' => 6,
        'max_parallel' => 6,
        'resolvers' => [
            'cloudflare' => ['label' => 'Cloudflare (1.1.1.1)', 'url' => 'https://cloudflare-dns.com/dns-query'],
            'google' => ['label' => 'Google (8.8.8.8)', 'url' => 'https://dns.google/resolve'],
            'quad9' => ['label' => 'Quad9 (9.9.9.9)', 'url' => 'https://dns.quad9.net:5053/dns-query'],
        ],
        'default_resolver' => 'cloudflare',
    ],
    // Standardwerte für application_settings
    'defaults' => [
        'cache_ttl' => '300',
        'cert_warn_days' => '30,14,7',
        'domain_warn_days' => '60,30,14',
        'stale_hours' => '48',
        'whois_fallback' => '1',
        'dkim_autoscan' => '0',
        'subdomain_resolve' => '1',
        'subdomain_resolve_limit' => '60',
        'dkim_selectors' => '',
        'tls_ports' => '443',
        'active_http' => '1',
        'starttls_check' => '0',
    ],
];

<?php
declare(strict_types=1);

namespace DomainScope\Support;

final class Request
{
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $query,
        public readonly array $post,
        public readonly array $server,
        public array $params = [],
    ) {
    }

    public static function capture(): self
    {
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = rawurldecode((string) parse_url($uri, PHP_URL_PATH));
        $path = '/' . trim(preg_replace('#/+#', '/', $path) ?? '/', '/');
        return new self(strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')), $path, $_GET, $_POST, $_SERVER);
    }

    public function input(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] ?? $this->query[$key] ?? $default;
    }

    public function has(string $key): bool
    {
        return isset($this->post[$key]) || isset($this->query[$key]);
    }

    public function str(string $key, string $default = ''): string
    {
        $v = $this->input($key, $default);
        return is_string($v) ? trim($v) : $default;
    }

    public function int(string $key, int $default = 0): int
    {
        $v = $this->input($key);
        return is_numeric($v) ? (int) $v : $default;
    }

    public function isPost(): bool
    {
        return $this->method === 'POST';
    }

    public function isAjax(): bool
    {
        return ($this->server['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch'
            || str_contains((string) ($this->server['HTTP_ACCEPT'] ?? ''), 'application/json');
    }

    public function header(string $name): string
    {
        return (string) ($this->server['HTTP_' . strtoupper(str_replace('-', '_', $name))] ?? '');
    }

    /** Client-IP; X-Forwarded-For nur von konfiguriertem Reverse Proxy. */
    public function ip(): string
    {
        $remote = (string) ($this->server['REMOTE_ADDR'] ?? '0.0.0.0');
        $proxy = (string) Config::get('app.trusted_proxy', '');
        if ($proxy !== '' && $remote === $proxy) {
            $fwd = trim(explode(',', $this->header('X-Forwarded-For'))[0] ?? '');
            if (filter_var($fwd, FILTER_VALIDATE_IP)) {
                return $fwd;
            }
        }
        return $remote;
    }

    public function isHttps(): bool
    {
        if (!empty($this->server['HTTPS']) && $this->server['HTTPS'] !== 'off') {
            return true;
        }
        $proxy = (string) Config::get('app.trusted_proxy', '');
        return $proxy !== '' && ($this->server['REMOTE_ADDR'] ?? '') === $proxy
            && strtolower($this->header('X-Forwarded-Proto')) === 'https';
    }
}

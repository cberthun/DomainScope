<?php
declare(strict_types=1);

namespace DomainScope\Support;

/** Minimaler Router: Pfadmuster mit {param} und {param:regex}. */
final class Router
{
    /** @var array<int,array{0:string,1:string,2:callable|array,3:array}> */
    private array $routes = [];

    public function add(string $method, string $pattern, callable|array $handler, array $options = []): void
    {
        $this->routes[] = [strtoupper($method), $pattern, $handler, $options];
    }

    public function get(string $pattern, callable|array $handler, array $options = []): void
    {
        $this->add('GET', $pattern, $handler, $options);
    }

    public function post(string $pattern, callable|array $handler, array $options = []): void
    {
        $this->add('POST', $pattern, $handler, $options);
    }

    /** @return array{handler:callable|array,params:array,options:array}|null */
    public function match(string $method, string $path): ?array
    {
        foreach ($this->routes as [$m, $pattern, $handler, $options]) {
            if ($m !== $method) {
                continue;
            }
            $regex = preg_replace_callback('/\{(\w+)(?::([^}]+))?\}/', static function (array $mt): string {
                return '(?P<' . $mt[1] . '>' . ($mt[2] ?? '[^/]+') . ')';
            }, $pattern);
            if (preg_match('#^' . $regex . '$#', $path, $found)) {
                $params = array_filter($found, 'is_string', ARRAY_FILTER_USE_KEY);
                return ['handler' => $handler, 'params' => $params, 'options' => $options];
            }
        }
        return null;
    }

    public function pathExists(string $path): bool
    {
        foreach (['GET', 'POST'] as $m) {
            if ($this->match($m, $path) !== null) {
                return true;
            }
        }
        return false;
    }
}

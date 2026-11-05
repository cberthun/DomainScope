<?php
declare(strict_types=1);

namespace DomainScope\Support;

use DomainScope\Security\{Auth, Csrf, Session};

/** Anwendungskern: Sicherheits-Header, Zugriffsschutz, CSRF, Routing, Fehlerbehandlung. */
final class App
{
    private Router $router;

    public function __construct()
    {
        $this->router = new Router();
        (require dirname(__DIR__) . '/routes.php')($this->router);
    }

    public function run(?Request $request = null): void
    {
        $request ??= Request::capture();
        register_shutdown_function([DataSources::class, 'flush']);
        try {
            $response = $this->handle($request);
        } catch (\Throwable $e) {
            Logger::exception($e);
            $response = $this->errorPage(500, $e);
        }
        foreach ($this->securityHeaders($request) as $k => $v) {
            $response->headers[$k] ??= $v;
        }
        $response->send($request->method === 'HEAD');
    }

    public function handle(Request $request): Response
    {
        if ((bool) Config::get('app.force_https') && !$request->isHttps()) {
            $host = preg_replace('/[^A-Za-z0-9.:\[\]-]/', '', (string) ($request->server['HTTP_HOST'] ?? ''));
            return new Response('', 301, ['Location' => 'https://' . $host . ($request->server['REQUEST_URI'] ?? '/')]);
        }
        if (!Auth::ipAllowed($request)) {
            return $this->errorPage(403);
        }
        Session::start($request);

        $match = $this->router->match($request->method === 'HEAD' ? 'GET' : $request->method, $request->path);
        if ($match === null) {
            return $this->errorPage($this->router->pathExists($request->path) ? 405 : 404);
        }
        $public = (bool) ($match['options']['public'] ?? false);
        $request->params = $match['params'];

        if (!Auth::configured()) {
            return Response::html(View::partial('layouts/bare', [
                'title' => 'Einrichtung erforderlich',
                'content' => View::partial('pages/setup_required'),
            ]), 503);
        }
        if (!$public && !Auth::check()) {
            if ($request->isAjax() || str_starts_with($request->path, '/api/')) {
                return Response::json(['ok' => false, 'error' => 'Nicht angemeldet.'], 401);
            }
            Session::set('intended', $request->method === 'GET' ? $request->path . (empty($request->query) ? '' : '?' . http_build_query($request->query)) : '/');
            return Response::redirect('/login');
        }
        if ($request->method === 'POST' && !Csrf::verify($request)) {
            if ($request->isAjax()) {
                return Response::json(['ok' => false, 'error' => 'Ungültiges CSRF-Token. Seite neu laden.'], 419);
            }
            return $this->errorPage(419);
        }

        // Lange AJAX-Prüfläufe sollen die Session nicht sperren (andere Tabs bleiben bedienbar)
        if ($request->isAjax() && $request->method === 'POST' && session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        [$class, $method] = $match['handler'];
        $controller = new $class($request);
        $result = $controller->$method($request);
        if ($result instanceof Response) {
            return $result;
        }
        return Response::html((string) $result);
    }

    /** @return array<string,string> */
    public function securityHeaders(Request $request): array
    {
        $h = [
            'Content-Security-Policy' => "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'Referrer-Policy' => 'no-referrer',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            'Cross-Origin-Opener-Policy' => 'same-origin',
            'Cross-Origin-Resource-Policy' => 'same-origin',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex, nofollow, noarchive',
        ];
        if ($request->isHttps()) {
            $h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
        }
        return $h;
    }

    private function errorPage(int $status, ?\Throwable $e = null): Response
    {
        $titles = [403 => 'Zugriff verweigert', 404 => 'Seite nicht gefunden', 405 => 'Methode nicht erlaubt', 419 => 'Sitzung abgelaufen', 500 => 'Interner Fehler'];
        $messages = [
            403 => 'Ihre IP-Adresse ist für diese Anwendung nicht freigegeben.',
            404 => 'Die angeforderte Seite existiert nicht.',
            405 => 'Diese Anfrage-Methode wird hier nicht unterstützt.',
            419 => 'Das Sicherheits-Token ist ungültig oder abgelaufen. Bitte die Seite neu laden und erneut versuchen.',
            500 => 'Beim Verarbeiten der Anfrage ist ein Fehler aufgetreten. Details stehen im Log.',
        ];
        $detail = ($e !== null && Config::get('app.debug')) ? get_class($e) . ': ' . $e->getMessage() . "\n" . $e->getFile() . ':' . $e->getLine() : null;
        $html = View::partial('layouts/bare', [
            'title' => $titles[$status] ?? 'Fehler',
            'content' => View::partial('pages/error', ['status' => $status, 'title' => $titles[$status] ?? 'Fehler', 'message' => $messages[$status] ?? '', 'detail' => $detail]),
        ]);
        return Response::html($html, $status);
    }
}

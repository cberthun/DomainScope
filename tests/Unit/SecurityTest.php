<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Security\{Auth, Csrf};
use DomainScope\Services\Http\{HostResolver, SafeHttp};
use DomainScope\Support\{Config, Logger, Request, Response};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SecurityTest extends TestCase
{
    protected function tearDown(): void
    {
        HostResolver::$override = null;
        SafeHttp::$transport = null;
        unset($_SESSION);
    }

    /**
     * Führt eine Anfrage im Kindprozess aus.
     *
     * @param array<string,mixed> $in
     * @return array{status:int,headers:array,body:string,session:array,session_id:string,flash:array}
     */
    private function request(array $in): array
    {
        // Konfigurationswerte im Kindprozess in Punktnotation relativ zu "app" (Standard: gesetztes Testpasswort)
        $in['config'] = ($in['config'] ?? []) + ['auth.password_hash' => password_hash('geheim-geheim-1', PASSWORD_BCRYPT, ['cost' => 4])];
        $cmd = [PHP_BINARY, __DIR__ . '/../Support/run_request.php', json_encode($in)];
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        proc_close($proc);
        $data = json_decode((string) $out, true);
        self::assertIsArray($data, "Kindprozess lieferte keine gültige Antwort: $out $err");
        return $data;
    }

    private function loggedIn(array $extra = []): array
    {
        return array_replace(['auth_user' => 'admin', 'last_activity' => time(), '_csrf' => str_repeat('ab', 32)], $extra);
    }

    // ---- Zugriffsschutz ------------------------------------------------------------------------------------

    #[DataProvider('protectedPaths')]
    public function testAnonymousUsersAreRedirectedToLogin(string $method, string $path): void
    {
        $r = $this->request(['method' => $method, 'path' => $path, 'post' => ['_csrf' => 'x']]);
        self::assertSame(302, $r['status'], "$method $path");
        self::assertSame('/login', $r['headers']['Location']);
        self::assertStringNotContainsString('Dashboard', $r['body']);
    }

    public static function protectedPaths(): array
    {
        return [
            ['GET', '/'], ['GET', '/domains'], ['GET', '/domain/example.com'], ['GET', '/dns'], ['GET', '/findings'], ['GET', '/settings'],
            ['GET', '/inventory'], ['GET', '/reports'], ['GET', '/monitoring'], ['GET', '/dns/export'], ['GET', '/subdomains/example.com/export'],
            ['POST', '/domain/example.com/run/dns'], ['POST', '/settings'], ['POST', '/inventory'], ['POST', '/logout'],
        ];
    }

    public function testApiReturns401JsonInsteadOfRedirect(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/api/search', 'query' => ['q' => 'abc']]);
        self::assertSame(401, $r['status']);
        self::assertStringContainsString('application/json', $r['headers']['Content-Type']);
    }

    public function testLoginPageIsPublicAndContainsCsrfToken(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/login']);
        self::assertSame(200, $r['status']);
        self::assertStringContainsString('name="_csrf"', $r['body']);
        self::assertStringContainsString('type="password"', $r['body']);
    }

    public function testAppRefusesToServeWithoutConfiguredPassword(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/', 'config' => ['auth.password_hash' => '']]);
        self::assertSame(503, $r['status']);
        self::assertStringContainsString('bin/setup.php', $r['body']);
        $r = $this->request(['method' => 'GET', 'path' => '/login', 'config' => ['auth.password_hash' => '']]);
        self::assertSame(503, $r['status'], 'Auch das Login ist ohne Passwort gesperrt');
    }

    public function testLoginSucceedsOnlyWithCorrectCredentialsAndCsrfToken(): void
    {
        $session = ['_csrf' => str_repeat('cd', 32)];
        $bad = $this->request(['method' => 'POST', 'path' => '/login', 'session' => $session, 'post' => ['_csrf' => $session['_csrf'], 'username' => 'admin', 'password' => 'falsch']]);
        self::assertSame(302, $bad['status']);
        self::assertSame('/login', $bad['headers']['Location']);
        self::assertArrayNotHasKey('auth_user', $bad['session']);

        $noCsrf = $this->request(['method' => 'POST', 'path' => '/login', 'session' => $session, 'post' => ['username' => 'admin', 'password' => 'geheim-geheim-1']]);
        self::assertSame(419, $noCsrf['status']);
        self::assertArrayNotHasKey('auth_user', $noCsrf['session']);

        $wrongUser = $this->request(['method' => 'POST', 'path' => '/login', 'session' => $session, 'post' => ['_csrf' => $session['_csrf'], 'username' => 'root', 'password' => 'geheim-geheim-1']]);
        self::assertArrayNotHasKey('auth_user', $wrongUser['session']);

        $ok = $this->request(['method' => 'POST', 'path' => '/login', 'session' => $session, 'post' => ['_csrf' => $session['_csrf'], 'username' => 'admin', 'password' => 'geheim-geheim-1']]);
        self::assertSame(302, $ok['status']);
        self::assertSame('/', $ok['headers']['Location']);
        self::assertSame('admin', $ok['session']['auth_user']);
        self::assertNotSame($session['_csrf'], $ok['session']['_csrf'], 'CSRF-Token wird nach Login erneuert');
    }

    public function testAuthenticatedSessionCanAccessAndIdleTimeoutExpires(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/login', 'session' => $this->loggedIn()]);
        self::assertSame(302, $r['status'], 'Angemeldete Nutzer werden vom Login weggeleitet');
        $page = $this->request(['method' => 'GET', 'path' => '/dns', 'session' => $this->loggedIn()]);
        self::assertSame(200, $page['status']);
        self::assertStringContainsString('DNS Explorer', $page['body']);

        $expired = $this->request(['method' => 'GET', 'path' => '/dns', 'session' => $this->loggedIn(['last_activity' => time() - 7200]), 'config' => ['auth.idle_timeout' => 3600]]);
        self::assertSame(302, $expired['status']);
        self::assertSame('/login', $expired['headers']['Location']);
    }

    public function testIpAllowlistBlocksForeignAddresses(): void
    {
        $deny = $this->request(['method' => 'GET', 'path' => '/login', 'config' => ['auth.ip_allowlist' => ['198.51.100.7']]]);
        self::assertSame(403, $deny['status']);
        $allow = $this->request(['method' => 'GET', 'path' => '/login', 'config' => ['auth.ip_allowlist' => ['203.0.113.5']]]);
        self::assertSame(200, $allow['status']);
    }

    public function testForwardedForIsIgnoredWithoutTrustedProxy(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/login', 'headers' => ['X-Forwarded-For' => '198.51.100.7'], 'config' => ['auth.ip_allowlist' => ['198.51.100.7']]]);
        self::assertSame(403, $r['status'], 'Gefälschter X-Forwarded-For darf die Allowlist nicht umgehen');
        $r = $this->request(['method' => 'GET', 'path' => '/login', 'headers' => ['X-Forwarded-For' => '198.51.100.7'], 'config' => ['auth.ip_allowlist' => ['198.51.100.7'], 'trusted_proxy' => '203.0.113.5']]);
        self::assertSame(200, $r['status']);
    }

    public function testRoutingErrors(): void
    {
        self::assertSame(404, $this->request(['method' => 'GET', 'path' => '/gibt-es-nicht'])['status']);
        self::assertSame(405, $this->request(['method' => 'GET', 'path' => '/logout'])['status']);
        self::assertSame(404, $this->request(['method' => 'GET', 'path' => '/app/bootstrap.php'])['status'], 'Interne PHP-Dateien sind nicht routbar');
        self::assertSame(404, $this->request(['method' => 'GET', 'path' => '/.env'])['status']);
    }

    // ---- CSRF ------------------------------------------------------------------------------------------

    public function testStateChangingRequestsRequireValidCsrfToken(): void
    {
        $s = $this->loggedIn();
        $none = $this->request(['method' => 'POST', 'path' => '/domains/lookup', 'session' => $s, 'post' => ['target' => 'example.com']]);
        self::assertSame(419, $none['status']);
        $wrong = $this->request(['method' => 'POST', 'path' => '/domains/lookup', 'session' => $s, 'post' => ['target' => 'example.com', '_csrf' => 'falsch']]);
        self::assertSame(419, $wrong['status']);
        $ajax = $this->request(['method' => 'POST', 'path' => '/domains/lookup', 'session' => $s, 'headers' => ['X-Requested-With' => 'fetch'], 'post' => ['target' => 'x']]);
        self::assertSame(419, $ajax['status']);
        self::assertStringContainsString('"ok":false', $ajax['body']);
        // Header-Token wird akzeptiert (AJAX): ungültige Eingabe führt zur Weiterleitung statt 419
        $hdr = $this->request(['method' => 'POST', 'path' => '/domains/lookup', 'session' => $s, 'headers' => ['X-CSRF-Token' => $s['_csrf']], 'post' => ['target' => '']]);
        self::assertSame(302, $hdr['status']);
    }

    public function testCsrfVerifyUsesConstantTimeComparisonOnSessionToken(): void
    {
        $_SESSION['_csrf'] = 'tok123';
        $mk = static fn(array $post, array $server = []) => new Request('POST', '/', [], $post, $server);
        self::assertTrue(Csrf::verify($mk(['_csrf' => 'tok123'])));
        self::assertTrue(Csrf::verify($mk([], ['HTTP_X_CSRF_TOKEN' => 'tok123'])));
        self::assertFalse(Csrf::verify($mk(['_csrf' => 'tok124'])));
        self::assertFalse(Csrf::verify($mk([])));
        $_SESSION['_csrf'] = '';
        self::assertFalse(Csrf::verify($mk(['_csrf' => ''])), 'Leeres Token ist nie gültig');
        $_SESSION = [];
        self::assertSame(64, strlen(Csrf::token()));
    }

    // ---- Sicherheits-Header & Ausgabe ---------------------------------------------------------------------

    public function testSecurityHeadersArePresent(): void
    {
        $h = $this->request(['method' => 'GET', 'path' => '/login'])['headers'];
        self::assertStringContainsString("default-src 'self'", $h['Content-Security-Policy']);
        self::assertStringContainsString("script-src 'self'", $h['Content-Security-Policy']);
        self::assertStringNotContainsString('unsafe-eval', $h['Content-Security-Policy']);
        self::assertStringContainsString("frame-ancestors 'none'", $h['Content-Security-Policy']);
        self::assertSame('nosniff', $h['X-Content-Type-Options']);
        self::assertSame('DENY', $h['X-Frame-Options']);
        self::assertSame('no-referrer', $h['Referrer-Policy']);
        self::assertSame('no-store', $h['Cache-Control']);
        self::assertArrayNotHasKey('Strict-Transport-Security', $h, 'HSTS nur über HTTPS');
        $https = $this->request(['method' => 'GET', 'path' => '/login', 'server' => ['HTTPS' => 'on']])['headers'];
        self::assertArrayHasKey('Strict-Transport-Security', $https);
    }

    public function testForceHttpsRedirects(): void
    {
        $r = $this->request(['method' => 'GET', 'path' => '/domains', 'server' => ['HTTP_HOST' => 'ds.example.org', 'REQUEST_URI' => '/domains'], 'config' => ['force_https' => true]]);
        self::assertSame(301, $r['status']);
        self::assertSame('https://ds.example.org/domains', $r['headers']['Location']);
    }

    public function testRedirectsCannotLeaveTheApplication(): void
    {
        foreach (['https://evil.example/', '//evil.example', "/ok\r\nSet-Cookie: x=1", 'javascript:alert(1)'] as $target) {
            self::assertSame('/', Response::redirect($target)->headers['Location'], $target);
        }
        self::assertSame('/domains?x=1', Response::redirect('/domains?x=1')->headers['Location']);
    }

    public function testDownloadFilenamesAreSanitized(): void
    {
        $r = Response::download('x', "../../etc/pass\"wd\r\n.csv", 'text/csv');
        self::assertStringNotContainsString('..', $r->headers['Content-Disposition']);
        self::assertStringNotContainsString("\n", $r->headers['Content-Disposition']);
        self::assertSame(1, preg_match('/^attachment; filename="[A-Za-z0-9._-]+"$/', $r->headers['Content-Disposition']));
    }

    public function testLogsDoNotContainSecrets(): void
    {
        $out = Logger::scrub('login password=hunter2 token: abc123 api_key="XYZ" Authorization: Bearer s3cr3t');
        foreach (['hunter2', 'abc123', 'XYZ', 's3cr3t'] as $secret) {
            self::assertStringNotContainsString($secret, $out);
        }
        self::assertStringNotContainsString("\n", Logger::scrub("a\nb"));
    }

    public function testAllowedIpCheckAndAuthConfiguration(): void
    {
        $cfg = (array) Config::get('app');
        $cfg['auth']['ip_allowlist'] = ['203.0.113.1'];
        Config::override('app', $cfg);
        try {
            $req = static fn(string $ip) => new Request('GET', '/', [], [], ['REMOTE_ADDR' => $ip]);
            self::assertTrue(Auth::ipAllowed($req('203.0.113.1')));
            self::assertFalse(Auth::ipAllowed($req('203.0.113.2')));
        } finally {
            $cfg['auth']['ip_allowlist'] = [];
            Config::override('app', $cfg);
        }
    }

    // ---- SSRF -------------------------------------------------------------------------------------------

    #[DataProvider('forbiddenUrls')]
    public function testForbiddenUrlsAreRejectedBeforeAnyConnection(string $url): void
    {
        HostResolver::$override = static fn(string $h) => match ($h) {
            'internal.example' => ['10.0.0.8'], 'loop.example' => ['127.0.0.1'], 'meta.example' => ['169.254.169.254'], 'v6loop.example' => ['::1'],
            'mixed.example' => ['93.184.216.34', '192.168.1.10'], 'public.example' => ['93.184.216.34'], default => [],
        };
        $called = false;
        SafeHttp::$transport = static function (array $hop) use (&$called): array {
            $called = true;
            return ['ok' => true, 'status' => 200, 'headers' => [], 'body' => '', 'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false];
        };
        $r = SafeHttp::request($url);
        self::assertFalse($r['ok'], $url);
        self::assertSame('blocked', $r['error_code'], $url);
        self::assertFalse($called, "Es darf keine Verbindung zu $url aufgebaut werden");
    }

    public static function forbiddenUrls(): array
    {
        return [
            ['http://127.0.0.1/'], ['http://127.0.0.1:8080/admin'], ['http://localhost/'], ['http://10.1.2.3/'], ['http://192.168.0.1/'],
            ['http://172.16.5.5/'], ['http://169.254.169.254/latest/meta-data/'], ['http://[::1]/'], ['http://[fe80::1]/'], ['http://[fd00::5]/'],
            ['http://0.0.0.0/'], ['http://100.64.0.1/'], ['http://internal.example/'], ['http://loop.example/'], ['http://meta.example/'],
            ['http://v6loop.example/'], ['http://mixed.example/'], ['http://[::ffff:127.0.0.1]/'],
            ['file:///etc/passwd'], ['gopher://public.example/'], ['ftp://public.example/'], ['dict://public.example:11211/'], ['javascript:alert(1)'],
            ['http://user:pass@public.example/'], ['http://public.example:22/'], ['http://public.example:3306/'], ['https://public.example:25/'],
            ['http://unresolvable.example/'], ['http://exa mple.com/'], ["http://public.example/\r\nHost: evil"], [''], ['//public.example'],
        ];
    }

    public function testRedirectsAreRevalidatedAtEveryHop(): void
    {
        HostResolver::$override = static fn(string $h) => $h === 'evil-redirect.example' ? ['93.184.216.34'] : ($h === 'rebind.example' ? ['10.9.9.9'] : ['93.184.216.40']);
        $seen = [];
        SafeHttp::$transport = static function (array $hop) use (&$seen): array {
            $seen[] = $hop['url'];
            $loc = match ($hop['url']) {
                'https://evil-redirect.example/start' => 'http://169.254.169.254/latest/meta-data/',
                'https://evil-redirect.example/rebind' => 'http://rebind.example/x',
                'https://evil-redirect.example/ip' => 'http://127.0.0.1:8080/',
                'https://evil-redirect.example/scheme' => 'file:///etc/passwd',
                default => null,
            };
            return ['ok' => $loc === null, 'status' => $loc ? 302 : 200, 'headers' => $loc ? ['location' => $loc] : [], 'body' => 'ok', 'final_url' => $hop['url'],
                'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false];
        };
        foreach (['start', 'rebind', 'ip', 'scheme'] as $path) {
            $seen = [];
            $r = SafeHttp::request('https://evil-redirect.example/' . $path);
            self::assertFalse($r['ok'], $path);
            self::assertSame('blocked', $r['error_code'], $path);
            self::assertCount(1, $seen, "Nur der erste Hop darf verbunden werden ($path)");
        }
    }

    public function testRedirectChainLimitAndRelativeLocations(): void
    {
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        $n = 0;
        SafeHttp::$transport = static function (array $hop) use (&$n): array {
            $n++;
            return ['ok' => true, 'status' => 302, 'headers' => ['location' => '/weiter' . $n], 'body' => '', 'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false];
        };
        $r = SafeHttp::request('https://loop.example/', ['max_redirects' => 3]);
        self::assertFalse($r['ok']);
        self::assertSame('redirects', $r['error_code']);
        self::assertSame(4, $n);
        self::assertSame('https://loop.example/weiter3', $r['redirects'][3]['url']);
    }

    public function testConnectionIsPinnedToValidatedIpAndTimeoutsAreReported(): void
    {
        $resolves = 0;
        HostResolver::$override = static function (string $h) use (&$resolves): array {
            return $resolves++ === 0 ? ['93.184.216.34'] : ['127.0.0.1']; // DNS-Rebinding: zweite Auflösung wäre intern
        };
        $pinned = null;
        SafeHttp::$transport = static function (array $hop) use (&$pinned): array {
            $pinned = $hop['ip'];
            return ['ok' => false, 'status' => 0, 'headers' => [], 'body' => '', 'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 12000, 'error' => 'timed out', 'error_code' => 'timeout', 'truncated' => false];
        };
        $r = SafeHttp::request('https://rebind-test.example/');
        self::assertSame('93.184.216.34', $pinned, 'Verbindung nutzt die einmal geprüfte IP');
        self::assertSame(1, $resolves, 'Es gibt genau eine Auflösung pro Hop');
        self::assertFalse($r['ok']);
        self::assertSame('timeout', $r['error_code']);
    }

    public function testValidateUrlAcceptsOrdinaryPublicTargets(): void
    {
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        foreach (['https://example.com/', 'http://example.com:8080/x?y=1', 'https://bücher.de/', 'https://93.184.216.34/'] as $url) {
            self::assertTrue(SafeHttp::validateUrl($url)['ok'], $url);
        }
        self::assertSame('xn--bcher-kva.de', SafeHttp::validateUrl('https://bücher.de/')['host']);
    }
}

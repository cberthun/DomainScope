<?php
declare(strict_types=1);

namespace DomainScope\Tests\Integration;

use DomainScope\Repositories\{CtRepository, FindingRepository};
use DomainScope\Security\{Credentials, Secrets, Totp};
use DomainScope\Support\{Config, Database};

/** Passwortwechsel, TOTP-Login und CT-Baseline gegen die Testdatenbank (Anfragen laufen im Kindprozess). */
final class AccountTest extends DatabaseTestCase
{
    private const KEY = 'test-app-key-0123456789abcdef0123456789abcdef0123456789';
    private string $origKey = '';

    protected function setUp(): void
    {
        parent::setUp();
        $cfg = (array) Config::get('app');
        $this->origKey = (string) $cfg['key'];
        $cfg['key'] = self::KEY;
        Config::override('app', $cfg);
        Credentials::reset();
    }

    protected function tearDown(): void
    {
        $cfg = (array) Config::get('app');
        $cfg['key'] = $this->origKey;
        Config::override('app', $cfg);
        Credentials::reset();
    }

    /** @return array<string,mixed> */
    private function req(array $in): array
    {
        $in['config'] = ($in['config'] ?? []) + ['key' => self::KEY, 'auth.password_hash' => ''];
        $proc = proc_open([PHP_BINARY, __DIR__ . '/../Support/run_request.php', json_encode($in)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        proc_close($proc);
        $d = json_decode((string) $out, true);
        self::assertIsArray($d, "Kindprozess: $out $err");
        return $d;
    }

    private function enableTotp(string $secret): array
    {
        Credentials::setPassword('Ein-sehr-langes-Passwort-1');
        Credentials::save(['totp_secret' => Secrets::encrypt($secret), 'totp_enabled' => 1, 'totp_last_counter' => 0]);
        return Credentials::newRecoveryCodes();
    }

    public function testPasswordFromDatabaseOverridesEnvAndLoginWorksWithoutTotp(): void
    {
        Credentials::setPassword('Ein-sehr-langes-Passwort-1');
        $s = ['_csrf' => str_repeat('ab', 32)];
        $bad = $this->req(['method' => 'POST', 'path' => '/login', 'session' => $s, 'post' => ['_csrf' => $s['_csrf'], 'username' => 'admin', 'password' => 'falsch']]);
        self::assertArrayNotHasKey('auth_user', $bad['session']);
        $ok = $this->req(['method' => 'POST', 'path' => '/login', 'session' => $s, 'post' => ['_csrf' => $s['_csrf'], 'username' => 'admin', 'password' => 'Ein-sehr-langes-Passwort-1']]);
        self::assertSame('/', $ok['headers']['Location']);
        self::assertSame('admin', $ok['session']['auth_user']);
    }

    public function testTotpLoginRequiresSecondFactorAndRejectsReplay(): void
    {
        $secret = Totp::generateSecret();
        $recovery = $this->enableTotp($secret);
        $s = ['_csrf' => str_repeat('ab', 32)];

        $step1 = $this->req(['method' => 'POST', 'path' => '/login', 'session' => $s, 'post' => ['_csrf' => $s['_csrf'], 'username' => 'admin', 'password' => 'Ein-sehr-langes-Passwort-1']]);
        self::assertSame('/login/2fa', $step1['headers']['Location']);
        self::assertArrayNotHasKey('auth_user', $step1['session'], 'nach dem Passwort noch nicht angemeldet');
        self::assertArrayHasKey('pending_2fa', $step1['session']);

        // geschützte Seite ist ohne zweiten Faktor weiterhin gesperrt
        $blocked = $this->req(['method' => 'GET', 'path' => '/domains', 'session' => ['pending_2fa' => $step1['session']['pending_2fa']]]);
        self::assertSame('/login', $blocked['headers']['Location']);

        $pending = ['pending_2fa' => ['user' => 'admin', 'at' => time()], '_csrf' => $s['_csrf']];
        $wrong = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $pending, 'post' => ['_csrf' => $s['_csrf'], 'code' => '000000']]);
        self::assertArrayNotHasKey('auth_user', $wrong['session']);
        self::assertSame(1, (int) Database::value('SELECT COUNT(*) FROM login_attempts'), 'Fehlversuch wird gezählt');

        $code = Totp::code($secret, intdiv(time(), 30));
        $ok = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $pending, 'post' => ['_csrf' => $s['_csrf'], 'code' => $code]]);
        self::assertSame('admin', $ok['session']['auth_user']);
        self::assertArrayNotHasKey('pending_2fa', $ok['session']);

        $replay = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $pending, 'post' => ['_csrf' => $s['_csrf'], 'code' => $code]]);
        self::assertArrayNotHasKey('auth_user', $replay['session'], 'derselbe Code ist nur einmal gültig');

        // Wiederherstellungscode: einmalig verwendbar
        $rc = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $pending, 'post' => ['_csrf' => $s['_csrf'], 'code' => $recovery[0]]]);
        self::assertSame('admin', $rc['session']['auth_user']);
        $again = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $pending, 'post' => ['_csrf' => $s['_csrf'], 'code' => $recovery[0]]]);
        self::assertArrayNotHasKey('auth_user', $again['session']);

        // ohne Passwortschritt kein Zugriff auf /login/2fa
        $direct = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => ['_csrf' => $s['_csrf']], 'post' => ['_csrf' => $s['_csrf'], 'code' => $code]]);
        self::assertArrayNotHasKey('auth_user', $direct['session']);
    }

    public function testExpiredPendingSecondFactorIsRejected(): void
    {
        $secret = Totp::generateSecret();
        $this->enableTotp($secret);
        $s = ['pending_2fa' => ['user' => 'admin', 'at' => time() - 3600], '_csrf' => str_repeat('ab', 32)];
        $r = $this->req(['method' => 'POST', 'path' => '/login/2fa', 'session' => $s, 'post' => ['_csrf' => $s['_csrf'], 'code' => Totp::code($secret, intdiv(time(), 30))]]);
        self::assertArrayNotHasKey('auth_user', $r['session']);
    }

    public function testTotpSecretIsStoredEncrypted(): void
    {
        $secret = Totp::generateSecret();
        $this->enableTotp($secret);
        $stored = (string) Database::value('SELECT totp_secret FROM auth_credentials WHERE id = 1');
        self::assertStringNotContainsString($secret, $stored);
        self::assertSame($secret, Credentials::decryptSecret());
        $codes = (string) Database::value('SELECT recovery_codes FROM auth_credentials WHERE id = 1');
        self::assertStringNotContainsString('-', str_replace('sha', '', $codes), 'Wiederherstellungscodes liegen nur als Hash vor');
    }

    public function testPasswordChangeRequiresCurrentPasswordAndMinimumLength(): void
    {
        Credentials::setPassword('Ein-sehr-langes-Passwort-1');
        $s = ['auth_user' => 'admin', 'last_activity' => time(), '_csrf' => str_repeat('cd', 32)];
        $post = static fn(array $p) => ['_csrf' => $s['_csrf']] + $p;
        $hash = fn() => (string) Database::value('SELECT password_hash FROM auth_credentials WHERE id = 1');
        $before = $hash();

        $this->req(['method' => 'POST', 'path' => '/account/password', 'session' => $s, 'post' => $post(['current_password' => 'falsch', 'new_password' => 'Neues-Passwort-12345', 'new_password2' => 'Neues-Passwort-12345'])]);
        self::assertSame($before, $hash(), 'falsches aktuelles Passwort');
        $this->req(['method' => 'POST', 'path' => '/account/password', 'session' => $s, 'post' => $post(['current_password' => 'Ein-sehr-langes-Passwort-1', 'new_password' => 'kurz', 'new_password2' => 'kurz'])]);
        self::assertSame($before, $hash(), 'zu kurz');
        $this->req(['method' => 'POST', 'path' => '/account/password', 'session' => $s, 'post' => $post(['current_password' => 'Ein-sehr-langes-Passwort-1', 'new_password' => 'Neues-Passwort-12345', 'new_password2' => 'abweichend-12345'])]);
        self::assertSame($before, $hash(), 'Wiederholung abweichend');

        $r = $this->req(['method' => 'POST', 'path' => '/account/password', 'session' => $s, 'post' => $post(['current_password' => 'Ein-sehr-langes-Passwort-1', 'new_password' => 'Neues-Passwort-12345', 'new_password2' => 'Neues-Passwort-12345'])]);
        self::assertSame('/account', $r['headers']['Location']);
        Credentials::reset();
        self::assertTrue(password_verify('Neues-Passwort-12345', $hash()));
        self::assertFalse(password_verify('Ein-sehr-langes-Passwort-1', $hash()));
    }

    public function testEnablingTotpFromTheAccountPage(): void
    {
        Credentials::setPassword('Ein-sehr-langes-Passwort-1');
        $s = ['auth_user' => 'admin', 'last_activity' => time(), '_csrf' => str_repeat('cd', 32)];
        $start = $this->req(['method' => 'POST', 'path' => '/account/2fa/start', 'session' => $s, 'post' => ['_csrf' => $s['_csrf']]]);
        $secret = $start['session']['totp_setup_secret'];
        self::assertNotEmpty($secret);
        $page = $this->req(['method' => 'GET', 'path' => '/account', 'session' => $start['session']]);
        self::assertStringContainsString(implode(' ', str_split($secret, 4)), $page['body'], 'Schlüssel wird zur manuellen Eingabe angezeigt');

        $bad = $this->req(['method' => 'POST', 'path' => '/account/2fa/enable', 'session' => $start['session'], 'post' => ['_csrf' => $s['_csrf'], 'code' => '123456']]);
        Credentials::reset();
        self::assertFalse(Credentials::totpEnabled(), 'falscher Bestätigungscode aktiviert nichts');

        $this->req(['method' => 'POST', 'path' => '/account/2fa/enable', 'session' => $start['session'], 'post' => ['_csrf' => $s['_csrf'], 'code' => Totp::code($secret, intdiv(time(), 30))]]);
        Credentials::reset();
        self::assertTrue(Credentials::totpEnabled());
        self::assertSame(8, Credentials::recoveryCodesLeft());
    }

    // ---- CT-Baseline ----------------------------------------------------------------------------------------

    private function cert(string $serial, string $issuer): array
    {
        return ['serial' => $serial, 'issuer' => $issuer, 'ct_id' => '1', 'names' => ['example.com'], 'not_before' => '2026-01-01 00:00:00', 'not_after' => '2026-04-01 00:00:00'];
    }

    public function testCtBaselineThenNewCertificatesWithKnownAndUnknownIssuers(): void
    {
        $id = (int) $this->domain()['id'];
        $first = CtRepository::saveScan($id, [$this->cert('01', 'R11'), $this->cert('02', 'R10')]);
        self::assertTrue($first['first']);
        self::assertSame([], $first['new'], 'Ausgangsbestand erzeugt keine Alarme');
        self::assertSame([], CtRepository::recentNew($id));

        $again = CtRepository::saveScan($id, [$this->cert('01', 'R11'), $this->cert('02', 'R10')]);
        self::assertSame([], $again['new']);

        $next = CtRepository::saveScan($id, [$this->cert('01', 'R11'), $this->cert('03', 'R11'), $this->cert('04', 'Evil CA')]);
        self::assertCount(2, $next['new']);
        $by = array_column($next['new'], null, 'serial');
        self::assertTrue($by['03']['known_issuer']);
        self::assertFalse($by['04']['known_issuer'], 'CA taucht erstmals auf');

        $drafts = \DomainScope\Findings\FindingsEngine::forCt('example.com', CtRepository::recentNew($id));
        $r = FindingRepository::reconcile($id, 'ct', $drafts);
        self::assertSame(2, $r['created']);
        $f = array_column(FindingRepository::search(['domain_id' => $id]), null, 'subject');
        self::assertSame('medium', $f['04']['severity']);
        self::assertSame('info', $f['03']['severity']);
        // Nach Bestätigung durch den Nutzer bleibt das Finding geschlossen
        FindingRepository::setStatus((int) $f['04']['id'], 'ignored', 'selbst beantragt');
        FindingRepository::reconcile($id, 'ct', $drafts);
        self::assertSame('ignored', FindingRepository::find((int) $f['04']['id'])['status']);
    }

    public function testOwnObservedIssuersCountAsKnown(): void
    {
        $id = (int) $this->domain()['id'];
        Database::insert('certificates', ['fingerprint_sha256' => str_repeat('a', 64), 'subject' => 'CN=example.com', 'issuer' => "C=US, O=Test, CN=Meine CA", 'first_seen' => Database::now()]);
        $certId = (int) Database::value('SELECT id FROM certificates LIMIT 1');
        Database::insert('tls_checks', ['domain_id' => $id, 'host' => 'example.com', 'port' => 443, 'status' => 'ok', 'certificate_id' => $certId, 'checked_at' => Database::now()]);
        CtRepository::saveScan($id, [$this->cert('01', 'R11')]);
        $new = CtRepository::saveScan($id, [$this->cert('01', 'R11'), $this->cert('09', 'Meine CA')]);
        self::assertTrue($new['new'][0]['known_issuer'], 'CA aus eigenen TLS-Prüfungen gilt als bekannt');
    }
}

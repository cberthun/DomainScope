<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Findings\FindingsEngine;
use DomainScope\Security\{Secrets, Totp};
use DomainScope\Services\EmailSecurity\HardeningService;
use DomainScope\Services\Http\{HostResolver, SafeHttp};
use DomainScope\Services\Subdomains\{SubdomainDiscovery, TakeoverChecker};
use DomainScope\Services\TLS\SmtpTlsInspector;
use DomainScope\Support\Config;
use DomainScope\Tests\Support\FakeDns;
use PHPUnit\Framework\TestCase;

final class NewFeaturesTest extends TestCase
{
    protected function tearDown(): void
    {
        HostResolver::$override = null;
        SafeHttp::$transport = null;
        SmtpTlsInspector::$override = null;
    }

    // ---- TOTP ----------------------------------------------------------------------------------------

    public function testTotpMatchesRfc6238Vectors(): void
    {
        $secret = Totp::base32Encode('12345678901234567890');
        self::assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret);
        // RFC 6238 Anhang B (SHA-1, 8 Stellen)
        foreach ([59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471', 1234567890 => '89005924', 2000000000 => '69279037'] as $t => $code) {
            self::assertSame($code, Totp::code($secret, intdiv($t, 30), 8), "t=$t");
        }
        self::assertSame('287082', Totp::code($secret, 1));
    }

    public function testTotpVerificationWindowAndReplayProtection(): void
    {
        $secret = Totp::generateSecret();
        $now = 1_800_000_000;
        $counter = intdiv($now, 30);
        $code = Totp::code($secret, $counter);
        self::assertSame($counter, Totp::verify($secret, $code, 0, $now));
        self::assertSame($counter, Totp::verify($secret, substr($code, 0, 3) . ' ' . substr($code, 3), 0, $now), 'Leerzeichen werden toleriert');
        self::assertNull(Totp::verify($secret, $code, $counter, $now), 'bereits verwendeter Code (Replay)');
        self::assertSame($counter - 1, Totp::verify($secret, Totp::code($secret, $counter - 1), 0, $now), 'ein Fenster Toleranz');
        self::assertNull(Totp::verify($secret, Totp::code($secret, $counter - 3), 0, $now), 'zu alt');
        self::assertNull(Totp::verify($secret, '12345', 0, $now));
        self::assertNull(Totp::verify($secret, 'abcdef', 0, $now));
        self::assertNull(Totp::verify('!!!', '123456', 0, $now));
        self::assertSame($secret, Totp::base32Encode(Totp::base32Decode($secret)));
        self::assertStringStartsWith('otpauth://totp/DomainScope%3Aadmin?secret=' . $secret, Totp::uri($secret, 'admin'));
    }

    public function testSecretsEncryptionIsAuthenticated(): void
    {
        $cfg = (array) Config::get('app');
        $orig = $cfg['key'];
        $cfg['key'] = str_repeat('k', 64);
        Config::override('app', $cfg);
        try {
            $blob = Secrets::encrypt('GEHEIM123');
            self::assertStringNotContainsString('GEHEIM', $blob);
            self::assertNotSame($blob, Secrets::encrypt('GEHEIM123'), 'zufälliger IV');
            self::assertSame('GEHEIM123', Secrets::decrypt($blob));
            $raw = base64_decode($blob);
            $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);
            self::assertNull(Secrets::decrypt(base64_encode($raw)), 'Manipulation wird erkannt');
            self::assertNull(Secrets::decrypt('kaputt'));
            $cfg['key'] = str_repeat('x', 64);
            Config::override('app', $cfg);
            self::assertNull(Secrets::decrypt($blob), 'anderer Schlüssel');
            $cfg['key'] = '';
            Config::override('app', $cfg);
            $this->expectException(\RuntimeException::class);
            Secrets::encrypt('x');
        } finally {
            $cfg['key'] = $orig;
            Config::override('app', $cfg);
        }
    }

    // ---- Takeover ------------------------------------------------------------------------------------

    public function testProviderMatching(): void
    {
        self::assertSame('GitHub Pages', TakeoverChecker::match('user.github.io.')['provider']);
        self::assertSame('Heroku', TakeoverChecker::match('app-123.herokuapp.com')['provider']);
        self::assertSame('AWS S3', TakeoverChecker::match('bucket.s3.eu-central-1.amazonaws.com')['provider']);
        self::assertNull(TakeoverChecker::match('www.example.org'));
        self::assertNull(TakeoverChecker::match('evilgithub.io.example.org'), 'Endung muss exakt passen');
    }

    public function testTakeoverDetectionUsesNxdomainAndProviderFingerprints(): void
    {
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        $fake = (new FakeDns())
            ->set('gone.herokuapp.com', 'A', [], 3)->set('gone.example.org', 'A', [], 3)
            ->set('ok.github.io', 'A', [['A', '185.199.108.153']])->set('empty.github.io', 'A', [['A', '185.199.108.153']])
            ->set('plain.example.net', 'A', [['A', '192.0.2.1']]);
        $body = static fn(string $url) => str_contains($url, 'docs.') ? "<h1>There isn't a GitHub Pages site here.</h1>" : '<h1>Willkommen</h1>';
        SafeHttp::$transport = static fn(array $hop) => ['ok' => true, 'status' => 404, 'headers' => [], 'body' => $body($hop['url']), 'final_url' => $hop['url'],
            'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false];
        $c = new TakeoverChecker($fake->client());

        $r = $c->check('shop.example.com', 'gone.herokuapp.com');
        self::assertSame('vulnerable', $r['status'], 'Heroku-Ziel existiert nicht');
        self::assertSame('Heroku', $r['provider']);
        $r = $c->check('old.example.com', 'gone.example.org');
        self::assertSame('dangling', $r['status'], 'unbekannter Anbieter: nur "dangling"');
        self::assertSame('vulnerable', $c->check('docs.example.com', 'empty.github.io')['status'], 'Fehlerseite von GitHub Pages');
        self::assertSame('provider', $c->check('blog.example.com', 'ok.github.io')['status']);
        self::assertSame('none', $c->check('x.example.com', 'plain.example.net')['status']);
        $slow = new FakeDns();
        $slow->failWith = 'timeout';
        self::assertSame('none', (new TakeoverChecker($slow->client()))->check('a.example.com', 'gone.herokuapp.com')['status'], 'DNS-Ausfall ist kein Befund');
    }

    public function testTakeoverFindingsSeverity(): void
    {
        $v = ['status' => 'vulnerable', 'provider' => 'Heroku', 'cname' => 'gone.herokuapp.com', 'evidence' => 'Ziel existiert nicht.', 'checked_at' => 'x'];
        $d = ['status' => 'dangling', 'provider' => null, 'cname' => 'x.example.org', 'evidence' => 'NXDOMAIN', 'checked_at' => 'x'];
        $f = FindingsEngine::forSubdomains('example.com', [
            'a.example.com' => ['status' => 'dangling_cname', 'ips' => [], 'cname' => 'gone.herokuapp.com'],
            'b.example.com' => ['status' => 'dangling_cname', 'ips' => [], 'cname' => 'x.example.org'],
            'c.example.com' => ['status' => 'dangling_cname', 'ips' => [], 'cname' => 'y.example.org'],
            'd.example.com' => ['status' => 'resolves', 'ips' => ['192.0.2.1'], 'cname' => null],
        ], ['a.example.com' => $v, 'b.example.com' => $d]);
        $by = array_column($f, null, 'subject');
        self::assertSame('subdomain.takeover', $by['a.example.com']['rule_id']);
        self::assertSame('high', $by['a.example.com']['severity']);
        self::assertStringContainsString('kein Ausnutzbarkeitsnachweis', $by['a.example.com']['reasoning']);
        self::assertSame('medium', $by['b.example.com']['severity']);
        self::assertSame('low', $by['c.example.com']['severity'], 'ohne Takeover-Test nur niedrig');
        self::assertArrayNotHasKey('d.example.com', $by);
    }

    // ---- CT ------------------------------------------------------------------------------------------

    public function testCtDiscoveryExtractsCertificatesForTheDomainOnly(): void
    {
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        $json = json_encode([
            ['id' => 1, 'issuer_name' => 'C=US, O=Let\'s Encrypt, CN=R11', 'serial_number' => '0abc', 'name_value' => "example.com\nwww.example.com", 'not_before' => '2026-01-01T00:00:00', 'not_after' => '2026-04-01T00:00:00'],
            ['id' => 2, 'issuer_name' => 'C=US, O=Let\'s Encrypt, CN=R11', 'serial_number' => '0abc', 'name_value' => 'example.com', 'not_before' => '2026-01-01T00:00:00', 'not_after' => '2026-04-01T00:00:00'],
            ['id' => 3, 'issuer_name' => 'CN=Evil CA', 'serial_number' => 'ff01', 'name_value' => "*.example.com\nother.org", 'not_before' => '2026-02-01T00:00:00', 'not_after' => '2026-05-01T00:00:00'],
            ['id' => 4, 'issuer_name' => 'CN=X', 'serial_number' => '01', 'name_value' => 'unrelated.org'],
        ]);
        SafeHttp::$transport = static fn(array $hop) => str_contains($hop['url'], 'crt.sh')
            ? ['ok' => true, 'status' => 200, 'headers' => [], 'body' => $json, 'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false]
            : ['ok' => false, 'status' => 429, 'headers' => [], 'body' => '', 'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 1, 'error' => null, 'error_code' => null, 'truncated' => false];
        $r = (new SubdomainDiscovery())->discover('example.com');
        self::assertCount(2, $r['certs'], 'Precert/Final mit gleicher Seriennummer werden zusammengeführt, fremde Domains verworfen');
        $by = array_column($r['certs'], null, 'serial');
        self::assertSame('R11', $by['abc']['issuer']);
        self::assertSame(['example.com', 'www.example.com'], $by['abc']['names']);
        self::assertSame(['*.example.com'], $by['ff01']['names'], 'nur Namen der eigenen Domain');
        self::assertArrayHasKey('certspotter', $r['errors']);
    }

    public function testCtFindingsDistinguishKnownAndUnknownIssuers(): void
    {
        $row = static fn(int $known) => ['serial' => 'ff01', 'issuer' => 'Evil CA', 'known_issuer' => $known, 'names_list' => ['*.example.com'], 'not_before' => '2026-02-01', 'not_after' => '2026-05-01', 'ct_id' => '3', 'first_seen' => '2026-02-02'];
        $f = FindingsEngine::forCt('example.com', [$row(0)])[0];
        self::assertSame('ct.unknown_issuer', $f['rule_id']);
        self::assertSame('medium', $f['severity']);
        self::assertStringContainsString('kein Nachweis', $f['reasoning']);
        $f = FindingsEngine::forCt('example.com', [$row(1)])[0];
        self::assertSame('ct.new_certificate', $f['rule_id']);
        self::assertSame('info', $f['severity']);
        self::assertSame([], FindingsEngine::forCt('example.com', []));
    }

    // ---- Härtung -------------------------------------------------------------------------------------

    private function caa(array $records, array $issuers = []): array
    {
        $fake = (new FakeDns())->set('example.com', 'CAA', array_map(static fn($r) => ['CAA', $r], $records));
        return (new HardeningService($fake->lookup()))->caa('example.com', $issuers);
    }

    private function codes(array $r): array
    {
        return array_column($r['findings'], 'code');
    }

    public function testCaaAnalysis(): void
    {
        self::assertContains('caa.missing', $this->codes($this->caa([])));
        $ok = $this->caa(['0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:sec@example.com"']);
        self::assertSame([], $this->codes($ok));
        self::assertSame(['letsencrypt.org'], $ok['issue']);
        self::assertContains('caa.no_iodef', $this->codes($this->caa(['0 issue "letsencrypt.org"'])));
        self::assertContains('caa.no_issue', $this->codes($this->caa(['0 iodef "mailto:a@example.com"'])));
        self::assertContains('caa.broad', $this->codes($this->caa(['0 issue "a.example"', '0 issue "b.example"', '0 issue "c.example"', '0 issue "d.example"'])));
        self::assertTrue($this->caa(['0 issue ";"'])['allows_none']);
    }

    public function testCaaIssuerMismatchUsesCertificateIssuer(): void
    {
        $le = "C=US, O=Let's Encrypt, CN=R11";
        $mismatch = $this->caa(['0 issue "digicert.com"', '0 iodef "mailto:a@example.com"'], [$le]);
        self::assertContains('caa.issuer_mismatch', $this->codes($mismatch));
        $okRes = $this->caa(['0 issue "letsencrypt.org"', '0 iodef "mailto:a@example.com"'], [$le]);
        self::assertNotContains('caa.issuer_mismatch', $this->codes($okRes));
        self::assertContains('caa.issuer_mismatch', $this->codes($this->caa(['0 issue ";"'], [$le])), 'CAA verbietet alle CAs');
        self::assertNotContains('caa.issuer_mismatch', $this->codes($this->caa(['0 issue "digicert.com"'], ['CN=Unbekannte Privat-CA'])), 'unbekannte CA: keine Aussage');
    }

    public function testCaaLookupFailureIsUnknownNotMissing(): void
    {
        $fake = new FakeDns();
        $fake->failWith = 'timeout';
        $r = (new HardeningService($fake->lookup()))->caa('example.com', []);
        self::assertSame(['caa.unknown'], $this->codes($r));
    }

    public function testDaneRequiresDnssec(): void
    {
        $fake = (new FakeDns())->set('_25._tcp.mx.example.com', 'TLSA', [['TLSA', '3 1 1 ' . str_repeat('ab', 32)]]);
        $svc = new HardeningService($fake->lookup());
        self::assertContains('dane.no_dnssec', array_column($svc->tlsa('example.com', ['mx.example.com'], 'unsigned')['findings'], 'code'));
        self::assertContains('dane.present', array_column($svc->tlsa('example.com', ['mx.example.com'], 'signed')['findings'], 'code'));
        $none = (new HardeningService((new FakeDns())->lookup()))->tlsa('example.com', ['mx.example.com'], 'unsigned');
        self::assertSame(['dane.none'], array_column($none['findings'], 'code'));
        self::assertSame('info', $none['findings'][0]['level']);
    }

    public function testStarttlsResultsAreMappedToFindings(): void
    {
        $base = ['port' => 25, 'ip' => '93.184.216.34', 'banner' => '220 x', 'protocol' => 'TLSv1.3', 'certificate' => null, 'hostname_match' => null,
            'chain_trusted' => null, 'trust_error' => null, 'days_left' => 60, 'expired' => false, 'error' => null, 'starttls' => true];
        SmtpTlsInspector::$override = static fn(string $h) => match ($h) {
            'blocked.example' => ['host' => $h, 'status' => 'unreachable', 'error' => 'Timeout'] + $base,
            'plain.example' => ['host' => $h, 'status' => 'no_starttls', 'starttls' => false] + $base,
            'expired.example' => ['host' => $h, 'status' => 'invalid', 'expired' => true, 'days_left' => -4, 'hostname_match' => true, 'chain_trusted' => false, 'trust_error' => 'abgelaufen'] + $base,
            'old.example' => ['host' => $h, 'status' => 'ok', 'protocol' => 'TLSv1', 'hostname_match' => false, 'chain_trusted' => true] + $base,
            default => ['host' => $h, 'status' => 'ok', 'hostname_match' => true, 'chain_trusted' => true] + $base,
        };
        $svc = new HardeningService((new FakeDns())->lookup());
        $r = $svc->starttls(['blocked.example', 'plain.example', 'expired.example', 'old.example', 'good.example']);
        $by = [];
        foreach ($r['findings'] as $f) {
            $by[$f['subject']][] = $f['code'];
        }
        self::assertSame(['starttls.unreachable'], $by['blocked.example']);
        self::assertSame(['starttls.missing'], $by['plain.example']);
        self::assertContains('starttls.expired', $by['expired.example']);
        self::assertNotContains('starttls.untrusted', $by['expired.example'], 'abgelaufen wird nicht doppelt gemeldet');
        self::assertContains('starttls.legacy', $by['old.example']);
        self::assertContains('starttls.hostname', $by['old.example']);
        self::assertArrayNotHasKey('good.example', $by);

        $drafts = FindingsEngine::forHardening('example.com', ['caa' => ['findings' => []], 'tlsa' => ['findings' => []], 'starttls' => $r]);
        $sev = array_column($drafts, 'severity', 'rule_id');
        self::assertSame('unknown', $sev['starttls.unreachable'], 'gesperrter Port 25 ist kein Sicherheitsbefund');
        self::assertSame('medium', $sev['starttls.missing']);
    }

    public function testStarttlsInspectorBlocksInternalTargets(): void
    {
        HostResolver::$override = static fn(string $h) => ['10.0.0.5'];
        $r = (new SmtpTlsInspector())->inspect('intern.example');
        self::assertSame('unreachable', $r['status']);
        self::assertStringContainsString('blockiert', (string) $r['error']);
    }
}

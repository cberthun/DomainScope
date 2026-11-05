<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Services\EmailSecurity\{DkimAnalyzer, DmarcAnalyzer, MtaStsAnalyzer, SpfAnalyzer, TlsRptAnalyzer};
use DomainScope\Services\Http\{HostResolver, SafeHttp};
use DomainScope\Tests\Support\FakeDns;
use PHPUnit\Framework\TestCase;

final class EmailSecurityTest extends TestCase
{
    private function codes(array $result): array
    {
        return array_column($result['findings'], 'code');
    }

    // ---- SPF ------------------------------------------------------------------------------------------------

    public function testSpfParsingOfMechanismsAndQualifiers(): void
    {
        $spf = new SpfAnalyzer((new FakeDns())->lookup());
        $p = $spf->parse('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com include:_spf.example.net -all');
        self::assertSame([], $p['errors']);
        self::assertSame(['ip4', 'ip6', 'a', 'mx', 'include', 'all'], array_column($p['terms'], 'mechanism'));
        self::assertSame('-', $p['terms'][5]['qualifier']);
        self::assertSame('192.0.2.0/24', $p['terms'][0]['value']);

        $p = $spf->parse('v=spf1 redirect=_spf.example.net exp=explain.example.com');
        self::assertSame('modifier', $p['terms'][0]['kind']);
        self::assertSame([], $p['errors']);

        $p = $spf->parse('v=spf1 include foo:bar ~all all:x -ALL');
        self::assertNotEmpty($p['errors'], 'include ohne Domain, unbekannter Mechanismus, all mit Parameter');
    }

    public function testSpfMissingAndMultipleRecords(): void
    {
        $dns = new FakeDns();
        $none = (new SpfAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertSame('none', $none['status']);
        self::assertContains('spf.missing', $this->codes($none));

        $dns->txt('example.com', 'v=spf1 -all', 'v=spf1 mx -all', 'google-site-verification=abc');
        $multi = (new SpfAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertSame('fail', $multi['status']);
        self::assertContains('spf.multiple', $this->codes($multi));
    }

    public function testSpfCountsDnsLookupsAcrossIncludesAndDetectsLimit(): void
    {
        $dns = new FakeDns();
        // Wurzel + 10 Includes = 10 Lookups genau am Limit, mit zusätzlichem "a" = 11 → PermError
        $inc = '';
        for ($i = 1; $i <= 10; $i++) {
            $inc .= " include:i$i.example.net";
            $dns->txt("i$i.example.net", 'v=spf1 ip4:192.0.2.' . $i . ' -all');
        }
        $dns->txt('ok.example', 'v=spf1' . $inc . ' -all');
        $ok = (new SpfAnalyzer($dns->lookup()))->analyze('ok.example');
        self::assertSame(10, $ok['lookups']);
        self::assertNotContains('spf.lookup_limit', $this->codes($ok));
        self::assertContains('spf.lookup_near_limit', $this->codes($ok));

        $dns->txt('over.example', 'v=spf1' . $inc . ' a -all');
        $dns->set('over.example', 'A', [['A', '192.0.2.50']]);
        $over = (new SpfAnalyzer($dns->lookup()))->analyze('over.example');
        self::assertSame(11, $over['lookups']);
        self::assertContains('spf.lookup_limit', $this->codes($over));
        self::assertSame('fail', $over['status']);
    }

    public function testSpfNestedIncludesAreCountedRecursively(): void
    {
        $dns = (new FakeDns())
            ->txt('root.example', 'v=spf1 include:a.example -all')
            ->txt('a.example', 'v=spf1 include:b.example mx -all')
            ->txt('b.example', 'v=spf1 a ip4:192.0.2.9 -all')
            ->set('a.example', 'MX', [['MX', '10 mx.a.example.']])
            ->set('b.example', 'A', [['A', '192.0.2.3']]);
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('root.example');
        // include a (1) + include b (2) + mx (3) + a (4)
        self::assertSame(4, $r['lookups']);
        self::assertSame('pass', $r['status']);
    }

    public function testSpfDetectsCyclesMissingIncludesAndVoidLookups(): void
    {
        $dns = (new FakeDns())
            ->txt('loop.example', 'v=spf1 include:loop2.example -all')
            ->txt('loop2.example', 'v=spf1 include:loop.example -all');
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('loop.example');
        self::assertContains('spf.loop', $this->codes($r));
        self::assertSame('fail', $r['status']);

        $dns = (new FakeDns())->txt('x.example', 'v=spf1 include:gone.example include:nospf.example -all')
            ->set('gone.example', 'TXT', [], 3)->txt('nospf.example', 'irgendein text');
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('x.example');
        $codes = $this->codes($r);
        self::assertContains('spf.include_missing', $codes);
        self::assertContains('spf.include_no_record', $codes);

        $dns = (new FakeDns())->txt('v.example', 'v=spf1 a:n1.example a:n2.example a:n3.example -all');
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('v.example');
        self::assertSame(3, $r['void_lookups']);
        self::assertContains('spf.void_limit', $this->codes($r));
    }

    public function testSpfPolicyEvaluation(): void
    {
        $cases = ['+all' => 'spf.plus_all', '?all' => 'spf.neutral_all', '~all' => 'spf.softfail_all', '-all' => 'spf.hardfail_all'];
        foreach ($cases as $all => $code) {
            $dns = (new FakeDns())->txt('p.example', "v=spf1 ip4:192.0.2.1 $all");
            self::assertContains($code, $this->codes((new SpfAnalyzer($dns->lookup()))->analyze('p.example')), $all);
        }
        $dns = (new FakeDns())->txt('p.example', 'v=spf1 ip4:192.0.2.1');
        self::assertContains('spf.no_all', $this->codes((new SpfAnalyzer($dns->lookup()))->analyze('p.example')));

        // redirect liefert die Policy des Ziels; "all" macht redirect wirkungslos
        $dns = (new FakeDns())->txt('r.example', 'v=spf1 redirect=t.example')->txt('t.example', 'v=spf1 -all');
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('r.example');
        self::assertSame('-', $r['policy']['qualifier']);
        self::assertTrue($r['policy']['via_redirect']);
        self::assertSame(1, $r['lookups']);
    }

    public function testSpfDnsFailureIsNotReportedAsMissingRecord(): void
    {
        $dns = new FakeDns();
        $dns->failWith = 'timeout';
        $r = (new SpfAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertSame('error', $r['status'], 'Ein Timeout darf nicht als "kein SPF" gewertet werden');
        self::assertNotContains('spf.missing', $this->codes($r));
    }

    // ---- DKIM -----------------------------------------------------------------------------------------------

    private function dkimRecord(int $bits, string $extra = ''): string
    {
        $key = \DomainScope\Tests\Support\Crypto::rsaKey($bits);
        $pub = openssl_pkey_get_details($key)['key'];
        $b64 = preg_replace('/-----[A-Z ]+-----|\s+/', '', $pub);
        return 'v=DKIM1; k=rsa; ' . $extra . 'p=' . $b64;
    }

    public function testDkimKeyInspection(): void
    {
        $dkim = new DkimAnalyzer((new FakeDns())->lookup());
        $good = $dkim->inspect($this->dkimRecord(2048), 'sel');
        self::assertSame('rsa', $good['key']['type']);
        self::assertSame(2048, $good['key']['bits']);
        self::assertSame([], $good['issues']);

        $short = $dkim->inspect($this->dkimRecord(1024), 'sel');
        self::assertContains('dkim.short_key', array_column($short['issues'], 'code'));
        $weak = $dkim->inspect($this->dkimRecord(512), 'sel');
        self::assertContains('dkim.weak_key', array_column($weak['issues'], 'code'));

        $testing = $dkim->inspect($this->dkimRecord(2048, 't=y; '), 'sel');
        self::assertContains('dkim.testing', array_column($testing['issues'], 'code'));
        $revoked = $dkim->inspect('v=DKIM1; k=rsa; p=', 'sel');
        self::assertContains('dkim.revoked', array_column($revoked['issues'], 'code'));
        $bad = $dkim->inspect('v=DKIM1; k=rsa; p=!!!nicht-base64!!!', 'sel');
        self::assertContains('dkim.bad_key', array_column($bad['issues'], 'code'));
        $nop = $dkim->inspect('v=DKIM1; k=rsa', 'sel');
        self::assertContains('dkim.no_p', array_column($nop['issues'], 'code'));
        $ed = $dkim->inspect('v=DKIM1; k=ed25519; p=' . base64_encode(random_bytes(32)), 'sel');
        self::assertSame('ed25519', $ed['key']['type']);
    }

    public function testDkimSelectorLookupAndHonestNegativeResult(): void
    {
        $dns = (new FakeDns())->txt('s1._domainkey.example.com', $this->dkimRecord(2048));
        $r = (new DkimAnalyzer($dns->lookup()))->analyze('example.com', ['s1', 'unbekannt', 'Ungültig Name!']);
        self::assertSame(1, $r['found']);
        self::assertCount(2, $r['selectors'], 'ungültige Selektornamen werden verworfen');
        self::assertSame('missing', $r['selectors'][1]['state']);

        $none = (new DkimAnalyzer((new FakeDns())->lookup()))->analyze('example.com', ['a', 'b']);
        self::assertSame('none', $none['status']);
        self::assertContains('dkim.none_found', $this->codes($none));
        $msg = implode(' ', array_column($none['findings'], 'message') + array_column($none['findings'], 'impact'));
        self::assertStringContainsString('anderem Selektor', implode(' ', array_filter(array_column($none['findings'], 'impact'))), 'Es wird nie behauptet, alle Selektoren geprüft zu haben');
        self::assertStringNotContainsString('alle Selektoren', $msg);
    }

    public function testDkimAutoscanIsBoundedAndRequiresExplicitFlag(): void
    {
        $fake = new FakeDns();
        (new DkimAnalyzer($fake->lookup()))->analyze('example.com', []);
        self::assertSame([], $fake->log, 'Ohne Selektoren und ohne Autoscan wird nichts abgefragt');

        $fake = new FakeDns();
        (new DkimAnalyzer($fake->lookup()))->analyze('example.com', [], true);
        self::assertLessThanOrEqual(60, count($fake->log));
        self::assertGreaterThan(10, count($fake->log));
        self::assertCount(count(DkimAnalyzer::COMMON_SELECTORS), $fake->log);
    }

    // ---- DMARC ----------------------------------------------------------------------------------------------

    public function testDmarcTagAnalysis(): void
    {
        $dns = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=r; rua=mailto:r@example.com; ruf=mailto:f@example.com');
        $r = (new DmarcAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertSame('reject', $r['policy']);
        self::assertTrue($r['enforcing']);
        self::assertSame('quarantine', $r['tags']['sp']);
        self::assertContains('dmarc.sp_weaker', $this->codes($r));
        self::assertContains('dmarc.ruf', $this->codes($r));
        $values = array_column($r['details'], 'value', 'label');
        self::assertStringContainsString('strict', $values['adkim (DKIM-Alignment)']);
        self::assertStringContainsString('relaxed', $values['aspf (SPF-Alignment)']);
    }

    public function testDmarcPolicyNoneAndPartialPercentage(): void
    {
        $dns = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=none');
        $r = (new DmarcAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertContains('dmarc.p_none', $this->codes($r));
        self::assertContains('dmarc.no_rua', $this->codes($r));
        self::assertFalse($r['enforcing']);
        self::assertSame('warn', $r['status']);

        $dns = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=quarantine; pct=25; rua=mailto:r@example.com');
        $r = (new DmarcAnalyzer($dns->lookup()))->analyze('example.com');
        self::assertContains('dmarc.pct', $this->codes($r));
        self::assertFalse($r['enforcing'], 'pct<100 gilt nicht als durchgesetzt');
    }

    public function testDmarcSyntaxErrorsAndMissingRecord(): void
    {
        $dns = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=banana; pct=150; adkim=x; rua=mailto:r@example.com');
        $codes = $this->codes((new DmarcAnalyzer($dns->lookup()))->analyze('example.com'));
        self::assertContains('dmarc.bad_p', $codes);
        self::assertContains('dmarc.bad_pct', $codes);
        self::assertContains('dmarc.bad_adkim', $codes);

        $missing = (new DmarcAnalyzer((new FakeDns())->lookup()))->analyze('example.com');
        self::assertSame('none', $missing['status']);
        self::assertContains('dmarc.missing', $this->codes($missing));

        $multi = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=none', 'v=DMARC1; p=reject');
        self::assertContains('dmarc.multiple', $this->codes((new DmarcAnalyzer($multi->lookup()))->analyze('example.com')));
    }

    public function testDmarcFallsBackToOrganizationalDomainAndChecksExternalAuthorization(): void
    {
        $dns = (new FakeDns())->txt('_dmarc.example.com', 'v=DMARC1; p=reject; rua=mailto:dmarc@reports.vendor.example');
        $r = (new DmarcAnalyzer($dns->lookup()))->analyze('www.example.com');
        self::assertTrue($r['inherited']);
        self::assertContains('dmarc.inherited', $this->codes($r));
        self::assertContains('dmarc.external_unauthorized', $this->codes($r), 'ohne Autorisierungs-Record beim Empfänger');

        $dns->txt('www.example.com._report._dmarc.reports.vendor.example', 'v=DMARC1');
        $r = (new DmarcAnalyzer($dns->lookup()))->analyze('www.example.com');
        self::assertNotContains('dmarc.external_unauthorized', $this->codes($r));
    }

    // ---- MTA-STS / TLS-RPT ----------------------------------------------------------------------------------

    public function testMtaStsPolicyParsing(): void
    {
        $a = new MtaStsAnalyzer((new FakeDns())->lookup());
        $p = $a->parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n");
        self::assertSame([], $p['errors']);
        self::assertSame('enforce', $p['mode']);
        self::assertSame(604800, $p['max_age']);
        self::assertSame(['mail.example.com', '*.example.net'], $p['mx']);

        $bad = $a->parsePolicy("version: STSv2\nmode: strict\nmax_age: abc\n");
        self::assertCount(4, $bad['errors']);
    }

    public function testMtaStsFullFlowWithMockedPolicyAndMxMismatch(): void
    {
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        SafeHttp::$transport = static fn(array $hop) => [
            'ok' => true, 'status' => 200, 'headers' => ['content-type' => 'text/plain; charset=utf-8'],
            'body' => "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n", 'final_url' => $hop['url'], 'ip' => '93.184.216.34',
            'redirects' => [], 'ms' => 4, 'error' => null, 'error_code' => null, 'truncated' => false,
        ];
        try {
            $dns = (new FakeDns())->txt('_mta-sts.example.com', 'v=STSv1; id=20240101');
            $r = (new MtaStsAnalyzer($dns->lookup()))->analyze('example.com', ['mail.example.com', 'other.example.org']);
            $codes = $this->codes($r);
            self::assertContains('mtasts.mx_mismatch', $codes);
            self::assertContains('mtasts.max_age_short', $codes);
            self::assertSame('fail', $r['status'], 'enforce mit nicht abgedecktem MX ist ein harter Befund');

            $ok = (new MtaStsAnalyzer($dns->lookup()))->analyze('example.com', ['mail.example.com']);
            self::assertNotContains('mtasts.mx_mismatch', $this->codes($ok));
        } finally {
            HostResolver::$override = null;
            SafeHttp::$transport = null;
        }
    }

    public function testMtaStsAndTlsRptAbsenceIsInformationalNotAFailure(): void
    {
        $mta = (new MtaStsAnalyzer((new FakeDns())->lookup()))->analyze('example.com', []);
        self::assertSame('none', $mta['status']);
        self::assertSame('bestpractice', $mta['findings'][0]['kind']);
        $rpt = (new TlsRptAnalyzer((new FakeDns())->lookup()))->analyze('example.com', false);
        self::assertSame('none', $rpt['status']);
    }

    public function testTlsRptValidation(): void
    {
        $dns = (new FakeDns())->txt('_smtp._tls.example.com', 'v=TLSRPTv1; rua=mailto:tls@example.com,https://report.example.com/x');
        $r = (new TlsRptAnalyzer($dns->lookup()))->analyze('example.com', true);
        self::assertSame('pass', $r['status']);
        $dns = (new FakeDns())->txt('_smtp._tls.example.com', 'v=TLSRPTv1; rua=ftp://nope');
        self::assertSame('fail', (new TlsRptAnalyzer($dns->lookup()))->analyze('example.com', true)['status']);
    }
}

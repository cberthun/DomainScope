<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Services\DNS\{DnsExplorerService, DnsTypes, RawDnsClient, RecordFormatter};
use DomainScope\Tests\Support\FakeDns;
use PHPUnit\Framework\TestCase;

final class DnsTest extends TestCase
{
    // ---- Parsing ------------------------------------------------------------------------------------

    public function testTxtNormalizationJoinsSegmentsAndHandlesEscapes(): void
    {
        self::assertSame('v=spf1 -all', RecordFormatter::txt('"v=spf1 -all"'));
        self::assertSame('abcdef', RecordFormatter::txt('"abc" "def"'));
        self::assertSame('say "hi"', RecordFormatter::txt('"say \"hi\""'));
        self::assertSame('plain value', RecordFormatter::txt('plain value'), 'Google liefert TXT ohne Anführungszeichen');
    }

    public function testNameAndMxNormalization(): void
    {
        self::assertSame('mail.example.com', RecordFormatter::normalize('MX', '10 Mail.Example.COM.') === '10 mail.example.com' ? 'mail.example.com' : 'x');
        self::assertSame('10 mail.example.com', RecordFormatter::normalize('MX', '10 Mail.Example.COM.'));
        self::assertSame('ns1.example.com', RecordFormatter::normalize('NS', 'NS1.Example.com.'));
        self::assertSame('2001:db8::1', RecordFormatter::normalize('AAAA', '2001:0db8:0000:0000:0000:0000:0000:0001'));
        self::assertSame(['priority' => 10, 'host' => 'mx.example.com'], RecordFormatter::parseMx('10 mx.example.com.'));
        self::assertNull(RecordFormatter::parseMx('kaputt'));
    }

    public function testSoaCaaDsParsing(): void
    {
        $soa = RecordFormatter::parseSoa('ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300');
        self::assertSame(2024010101, $soa['serial']);
        self::assertSame('ns1.example.com', $soa['mname']);
        self::assertNull(RecordFormatter::parseSoa('zu kurz'));

        self::assertSame(['flags' => 0, 'tag' => 'issue', 'value' => 'letsencrypt.org'], RecordFormatter::parseCaa('0 issue "letsencrypt.org"'));
        // Binäre Darstellung (RFC 3597): 0 issue "ca.example"
        $hex = bin2hex("\x00\x05issueca.example");
        self::assertSame(['flags' => 0, 'tag' => 'issue', 'value' => 'ca.example'], RecordFormatter::parseCaa('\\# ' . (strlen($hex) / 2) . ' ' . $hex));

        $ds = RecordFormatter::parseDs('2371 13 2 32996839A6D808AFAE3D0D9CC6A1BEFEB7C0B1B9D9D5E7D4C2D78F6E1F34E3AB');
        self::assertSame(2371, $ds['keytag']);
        self::assertSame(2, $ds['digest_type']);
        self::assertStringStartsWith('32996839', $ds['digest']);

        $rr = RecordFormatter::parseRrsig('DNSKEY 13 2 3600 20261213045538 20261016045538 2371 cloudflare.com. AAAA');
        self::assertSame('DNSKEY', $rr['covered']);
        self::assertSame(2371, $rr['keytag']);
        self::assertSame(gmmktime(4, 55, 38, 12, 13, 2026), $rr['expiration']);
    }

    // ---- DoH-Client: Statusunterscheidung ------------------------------------------------------------------

    public function testStatusDistinguishesNxdomainNodataServfailRefusedAndOk(): void
    {
        $fake = (new FakeDns())
            ->set('ok.example', 'A', [['A', '192.0.2.1']])
            ->set('nodata.example', 'AAAA', [])
            ->set('gone.example', 'A', [], 3)
            ->set('broken.example', 'A', [], 2)
            ->set('refused.example', 'A', [], 5);
        $doh = $fake->client();
        $statusOf = static fn(string $n, string $t = 'A') => $doh->query('cloudflare', $n, $t)['status'];
        self::assertSame('ok', $statusOf('ok.example'));
        self::assertSame('nodata', $statusOf('nodata.example', 'AAAA'));
        self::assertSame('nxdomain', $statusOf('gone.example'));
        self::assertSame('servfail', $statusOf('broken.example'));
        self::assertSame('refused', $statusOf('refused.example'));
        $ok = $doh->query('cloudflare', 'ok.example', 'A');
        self::assertSame('192.0.2.1', $ok['answer'][0]['data']);
        self::assertSame(300, $ok['answer'][0]['ttl']);
        self::assertSame('NOERROR', $ok['rcode_name']);
        self::assertSame(12, $ok['ms']);
    }

    public function testTimeoutAndTransportErrorsAreNotReportedAsDnsResults(): void
    {
        $fake = new FakeDns();
        $fake->failWith = 'timeout';
        $r = $fake->client()->query('cloudflare', 'example.com', 'A');
        self::assertSame('timeout', $r['status']);
        self::assertSame([], $r['answer']);
        self::assertNull($r['rcode']);
        self::assertStringContainsString('Resolver', $r['explanation']);

        $fake = new FakeDns();
        $fake->failWith = 'error';
        self::assertSame('error', $fake->client()->query('google', 'example.com', 'A')['status']);
    }

    public function testInvalidResolverAnswerIsAnError(): void
    {
        $doh = new \DomainScope\Services\DNS\DohClient(static fn() => ['body' => '<html>nope</html>', 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 3]);
        $r = $doh->query('cloudflare', 'example.com', 'A');
        self::assertSame('error', $r['status']);
        $doh = new \DomainScope\Services\DNS\DohClient(static fn() => ['body' => 'x', 'http' => 503, 'error' => null, 'errno' => 0, 'ms' => 3]);
        self::assertSame('error', $doh->query('cloudflare', 'example.com', 'A')['status']);
        self::assertSame('error', $doh->query('unbekannt', 'example.com', 'A')['status']);
    }

    public function testCnameOnlyAnswerIsNodataForOtherTypes(): void
    {
        $fake = (new FakeDns())->set('alias.example', 'A', [['CNAME', 'target.example.']]);
        $r = $fake->client()->query('cloudflare', 'alias.example', 'A');
        self::assertSame('nodata', $r['status'], 'CNAME ohne A-Ziel liefert keine A-Records');
        self::assertSame('CNAME', $r['answer'][0]['type']);
    }

    public function testQueryMemoizationAvoidsDuplicateRequests(): void
    {
        $fake = (new FakeDns())->set('a.example', 'A', [['A', '192.0.2.5']]);
        $doh = $fake->client();
        $doh->query('cloudflare', 'a.example', 'A');
        $doh->query('cloudflare', 'a.example', 'A');
        self::assertCount(1, $fake->log);
    }

    // ---- Explorer: Vergleich & Export -------------------------------------------------------------------------

    public function testResolverComparisonFindsDifferencesIgnoringTtl(): void
    {
        $fake = (new FakeDns())->set('example.com', 'A', [['A', '192.0.2.1']])->set('example.com', 'NS', [['NS', 'ns1.example.com.']]);
        $doh = new \DomainScope\Services\DNS\DohClient(function (string $url) use ($fake): array {
            $isGoogle = str_contains($url, 'dns.google');
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            $type = $q['type'];
            $answers = match ($type) {
                'A' => [['name' => 'example.com.', 'type' => 1, 'TTL' => $isGoogle ? 60 : 300, 'data' => $isGoogle ? '192.0.2.99' : '192.0.2.1']],
                'NS' => [['name' => 'example.com.', 'type' => 2, 'TTL' => $isGoogle ? 10 : 20, 'data' => 'ns1.example.com.']],
                default => [],
            };
            return ['body' => json_encode(['Status' => 0, 'Answer' => $answers]), 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 5];
        });
        $res = (new DnsExplorerService($doh))->lookup('example.com', ['A', 'NS'], ['cloudflare', 'google']);
        self::assertFalse($res['comparison']['A']['consistent']);
        self::assertTrue($res['comparison']['NS']['consistent'], 'TTL-Unterschiede sind keine Abweichung');
        self::assertContains('192.0.2.99', $res['comparison']['A']['missing_in']['cloudflare']);
    }

    public function testExplorerReverseLookupForIpAndTypeFiltering(): void
    {
        $fake = (new FakeDns())->set('4.3.2.1.in-addr.arpa', 'PTR', [['PTR', 'host.example.']]);
        $res = (new DnsExplorerService($fake->client()))->lookup('1.2.3.4', ['A', 'MX', 'FOO'], ['cloudflare']);
        self::assertSame(['PTR'], $res['types']);
        self::assertSame('4.3.2.1.in-addr.arpa', $res['query_name']);
        self::assertSame('host.example', $res['results']['cloudflare']['PTR']['answer'][0]['data']);
        $res = (new DnsExplorerService($fake->client()))->lookup('example.com', ['bogus'], ['evil-resolver']);
        self::assertSame(['A'], $res['types'], 'Unbekannte Typen werden verworfen');
        self::assertSame(['cloudflare'], $res['resolvers'], 'Unbekannte Resolver werden verworfen');
    }

    public function testCsvExportNeutralizesFormulaInjection(): void
    {
        $csv = DnsExplorerService::toCsv([['a' => '=HYPERLINK("http://evil")', 'b' => 'normal', 'c' => '@cmd', 'd' => "x,\"y\""]], ['a', 'b', 'c', 'd']);
        self::assertStringContainsString("'=HYPERLINK", $csv);
        self::assertStringContainsString("'@cmd", $csv);
        self::assertStringContainsString('"x,""y"""', $csv);
        self::assertStringStartsWith("\xEF\xBB\xBF", $csv);
    }

    public function testRequiredRecordTypesAreSupported(): void
    {
        foreach (['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'SRV', 'PTR', 'NAPTR', 'DS', 'DNSKEY'] as $t) {
            self::assertContains($t, DnsTypes::EXPLORER);
            self::assertNotNull(DnsTypes::code($t));
        }
    }

    // ---- Wire-Format ----------------------------------------------------------------------------------------

    public function testRawClientBuildsAndParsesWireMessages(): void
    {
        // Antwort für example.com A 192.0.2.1 mit Kompressionszeiger
        RawDnsClient::$transport = static function (string $ip, string $packet, bool $tcp): string {
            $id = unpack('n', substr($packet, 0, 2))[1];
            $q = RawDnsClient::nameToWire('example.com') . pack('nn', 1, 1);
            $hdr = pack('nnnnnn', $id, 0x8400, 1, 1, 0, 0);
            $ans = "\xC0\x0C" . pack('nnNn', 1, 1, 300, 4) . inet_pton('192.0.2.1');
            return $hdr . $q . $ans;
        };
        try {
            $res = (new RawDnsClient())->query('8.8.8.8', 'example.com', 'A');
            self::assertTrue($res['ok']);
            self::assertTrue($res['flags']['aa']);
            self::assertSame('192.0.2.1', $res['answer'][0]['data']);
            self::assertSame('example.com', $res['answer'][0]['name']);
            self::assertSame(300, $res['answer'][0]['ttl']);
        } finally {
            RawDnsClient::$transport = null;
        }
    }

    public function testRawClientTimeoutAndForbiddenTargets(): void
    {
        RawDnsClient::$transport = static fn() => null;
        try {
            $r = (new RawDnsClient())->query('8.8.8.8', 'example.com', 'SOA');
            self::assertFalse($r['ok']);
            self::assertStringContainsString('Timeout', (string) $r['error']);
        } finally {
            RawDnsClient::$transport = null;
        }
        foreach (['127.0.0.1', '10.0.0.5', '169.254.169.254', '::1'] as $bad) {
            $r = (new RawDnsClient())->query($bad, 'example.com', 'A');
            self::assertFalse($r['ok'], $bad);
            self::assertStringContainsString('blockiert', (string) $r['error']);
        }
    }

    public function testRawClientRejectsMismatchedIdAndTruncatedMessages(): void
    {
        RawDnsClient::$transport = static fn() => pack('nnnnnn', 1, 0x8400, 0, 0, 0, 0); // falsche ID
        try {
            $r = (new RawDnsClient())->query('8.8.8.8', 'example.com', 'A');
            self::assertFalse($r['ok']);
        } finally {
            RawDnsClient::$transport = null;
        }
        self::assertNull((new RawDnsClient())->parse('zu kurz', 1));
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Findings\FindingsEngine;
use DomainScope\Services\DNS\{RawDnsClient, RecordFormatter};
use DomainScope\Services\DNSSEC\{DnssecCrypto, DnssecService};
use DomainScope\Services\TLS\TlsInspector;
use DomainScope\Tests\Support\{Crypto, FakeDns};
use PHPUnit\Framework\TestCase;

final class TlsDnssecTest extends TestCase
{
    // ---- Zertifikate ----------------------------------------------------------------------------------

    public function testCertificateParsing(): void
    {
        $pem = Crypto::certificate(['cn' => 'www.example.test', 'sans' => ['www.example.test', 'example.test', '*.api.example.test'], 'days' => 30]);
        $c = (new TlsInspector())->parseCertificate($pem);
        self::assertNotNull($c);
        self::assertSame('www.example.test', $c['common_name']);
        self::assertSame(['www.example.test', 'example.test', '*.api.example.test'], $c['sans']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $c['fingerprint_sha256']);
        self::assertSame(hash('sha256', (string) base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem))), $c['fingerprint_sha256']);
        self::assertSame('RSA', $c['key_type']);
        self::assertSame(2048, $c['key_bits']);
        self::assertTrue($c['self_signed']);
        self::assertFalse($c['is_ca']);
        self::assertStringContainsString('sha256', strtolower((string) $c['signature_algorithm']));
        $days = (int) floor(($c['not_after_ts'] - time()) / 86400);
        self::assertGreaterThanOrEqual(29, $days);
        self::assertLessThanOrEqual(30, $days);
        self::assertNull((new TlsInspector())->parseCertificate('kein pem'));
    }

    public function testHostnameMatchingFollowsRfc6125(): void
    {
        $m = static fn(string $host, array $sans, ?string $cn = null) => TlsInspector::hostnameMatches($host, $sans, $cn);
        self::assertTrue($m('example.com', ['example.com']));
        self::assertTrue($m('EXAMPLE.com.', ['example.com']));
        self::assertTrue($m('www.example.com', ['*.example.com']));
        self::assertFalse($m('example.com', ['*.example.com']), 'Wildcard deckt die Basisdomain nicht ab');
        self::assertFalse($m('a.b.example.com', ['*.example.com']), 'Wildcard nur für ein Label');
        self::assertFalse($m('www.example.com', ['*.com']), 'Wildcard über TLD-Ebene unzulässig');
        self::assertFalse($m('evil-example.com', ['*example.com']), 'Partielle Wildcards unzulässig');
        self::assertTrue($m('legacy.example.com', [], 'legacy.example.com'), 'CN nur ohne SAN');
        self::assertFalse($m('cn-only.example.com', ['other.example.com'], 'cn-only.example.com'), 'CN wird ignoriert, wenn SAN vorhanden');
        self::assertFalse($m('192.0.2.1', ['192.0.2.1']), 'IP-Adressen werden nicht über DNS-SAN geprüft');
    }

    public function testInspectionOverrideAndBlockedTargets(): void
    {
        $i = new TlsInspector();
        $r = $i->inspect('localhost', 443, '127.0.0.1');
        self::assertSame('unreachable', $r['status']);
        self::assertSame('blocked', $r['error_stage']);
        $r = $i->inspect('example.com', 25, '93.184.216.34');
        self::assertSame('blocked', $r['error_stage'], 'Nicht freigegebene Ports werden abgewiesen');
        $r = $i->inspect('x.example', 443, '10.0.0.5');
        self::assertSame('blocked', $r['error_stage']);
    }

    public function testExpirySeverityThresholds(): void
    {
        $t = [30, 14, 7];
        self::assertNull(FindingsEngine::expirySeverity(60, $t));
        self::assertSame('low', FindingsEngine::expirySeverity(30, $t));
        self::assertSame('low', FindingsEngine::expirySeverity(20, $t));
        self::assertSame('medium', FindingsEngine::expirySeverity(14, $t));
        self::assertSame('medium', FindingsEngine::expirySeverity(10, $t));
        self::assertSame('high', FindingsEngine::expirySeverity(7, $t));
        self::assertSame('high', FindingsEngine::expirySeverity(1, $t));
        self::assertSame('medium', FindingsEngine::expirySeverity(5, [10]));
    }

    private function tlsResult(array $over = []): array
    {
        $cert = (new TlsInspector())->parseCertificate(Crypto::certificate(['cn' => 'example.test']));
        return array_replace_recursive([
            'host' => 'example.test', 'port' => 443, 'ip' => '93.184.216.34', 'status' => 'ok', 'reachable' => true, 'error' => null, 'error_stage' => null,
            'protocol' => 'TLSv1.3', 'chain_trusted' => true, 'trust_error' => null, 'hostname_match' => true, 'certificate' => $cert, 'chain' => [$cert],
            'days_left' => 80, 'expired' => false,
        ], $over);
    }

    public function testTlsFindingsDistinguishInvalidFromUnreachable(): void
    {
        self::assertSame([], FindingsEngine::forTls('example.test', [$this->tlsResult()]));

        $f = FindingsEngine::forTls('example.test', [$this->tlsResult(['days_left' => 5])]);
        self::assertSame('tls.expiring', $f[0]['rule_id']);
        self::assertSame('high', $f[0]['severity']);

        $f = FindingsEngine::forTls('example.test', [$this->tlsResult(['expired' => true, 'days_left' => -3, 'status' => 'invalid'])]);
        self::assertSame('tls.expired', $f[0]['rule_id']);
        self::assertSame('critical', $f[0]['severity']);

        $f = FindingsEngine::forTls('example.test', [$this->tlsResult(['hostname_match' => false, 'status' => 'invalid'])]);
        self::assertSame('tls.hostname_mismatch', $f[0]['rule_id']);

        $f = FindingsEngine::forTls('example.test', [$this->tlsResult(['chain_trusted' => false, 'trust_error' => 'Selbstsigniert', 'status' => 'invalid'])]);
        self::assertSame('tls.untrusted', $f[0]['rule_id']);

        // Nicht erreichbarer Host ≠ ungültiges Zertifikat → Schweregrad "Unbekannt"
        $f = FindingsEngine::forTls('example.test', [[
            'host' => 'mail.example.test', 'port' => 443, 'ip' => '93.184.216.34', 'status' => 'unreachable', 'error' => 'Verbindung abgelehnt',
            'error_stage' => 'connect', 'certificate' => null, 'chain' => [],
        ]]);
        self::assertSame('unknown', $f[0]['severity']);
        // Gar nicht auflösbar → kein Finding
        self::assertSame([], FindingsEngine::forTls('example.test', [['host' => 'x.example.test', 'port' => 443, 'ip' => null, 'status' => 'unreachable', 'error' => 'dns', 'error_stage' => 'dns', 'certificate' => null, 'chain' => []]]));
    }

    public function testVerifyErrorExplanations(): void
    {
        self::assertStringContainsString('abgelaufen', TlsInspector::explainVerifyError('certificate has expired'));
        self::assertStringContainsString('Selbstsigniert', TlsInspector::explainVerifyError('self-signed certificate'));
        self::assertStringContainsString('Intermediate', TlsInspector::explainVerifyError('unable to get local issuer certificate'));
    }

    // ---- DNSSEC-Kryptografie (Echtdaten-Fixture: cloudflare.com) -----------------------------------------------

    /** @return array{keys:array,rrsig:array,ds:array} */
    private function fixture(): array
    {
        $fx = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/dnssec_cloudflare.json'), true);
        $keys = [];
        $rrsig = null;
        foreach ($fx['DNSKEY'] as $r) {
            if ($r['type'] === 'DNSKEY') {
                $keys[] = RecordFormatter::parseDnskey($r['data']);
            } elseif ($r['type'] === 'RRSIG') {
                $rrsig = RecordFormatter::parseRrsig($r['data']);
            }
        }
        $ds = array_map(static fn($r) => RecordFormatter::parseDs($r['data']), array_values(array_filter($fx['DS'], static fn($r) => $r['type'] === 'DS')));
        return ['keys' => $keys, 'rrsig' => $rrsig, 'ds' => $ds];
    }

    public function testKeyTagAndDsDigestMatchRealCloudflareData(): void
    {
        $fx = $this->fixture();
        $ksk = null;
        foreach ($fx['keys'] as $k) {
            if (($k['flags'] & 1) === 1) {
                $ksk = $k;
            }
        }
        $rdata = DnssecCrypto::dnskeyRdata($ksk['flags'], $ksk['protocol'], $ksk['algorithm'], $ksk['key']);
        $tag = DnssecCrypto::keyTag($rdata);
        $matched = false;
        foreach ($fx['ds'] as $ds) {
            if ($ds['keytag'] === $tag) {
                self::assertSame($ds['digest'], DnssecCrypto::dsDigest('cloudflare.com', $rdata, $ds['digest_type']), 'DS-Digest muss exakt dem Registry-DS entsprechen');
                $matched = true;
            }
        }
        self::assertTrue($matched, 'Key-Tag des KSK taucht im DS auf');
        self::assertNull(DnssecCrypto::dsDigest('cloudflare.com', $rdata, 3), 'GOST wird nicht berechnet');
    }

    public function testDnskeyRrsigVerificationDetectsTampering(): void
    {
        $fx = $this->fixture();
        $signer = null;
        foreach ($fx['keys'] as $k) {
            $rd = DnssecCrypto::dnskeyRdata($k['flags'], $k['protocol'], $k['algorithm'], $k['key']);
            if (DnssecCrypto::keyTag($rd) === $fx['rrsig']['keytag']) {
                $signer = $k;
            }
        }
        self::assertNotNull($signer);
        $ok = DnssecCrypto::verifyDnskeyRrset('cloudflare.com', $fx['keys'], $fx['rrsig'], $signer);
        self::assertTrue($ok['valid'], $ok['reason']);

        $tampered = $fx['keys'];
        $tampered[0]['key'] = substr($tampered[0]['key'], 0, 10) . 'AAAA' . substr($tampered[0]['key'], 14);
        $bad = DnssecCrypto::verifyDnskeyRrset('cloudflare.com', $tampered, $fx['rrsig'], $signer);
        self::assertFalse($bad['valid'], 'Veränderter DNSKEY-Satz darf nicht validieren');

        $wrongOwner = DnssecCrypto::verifyDnskeyRrset('example.com', $fx['keys'], $fx['rrsig'], $signer);
        self::assertFalse($wrongOwner['valid']);
    }

    public function testAlgorithmClassification(): void
    {
        self::assertSame('ok', DnssecCrypto::algorithmStrength(13));
        self::assertSame('ok', DnssecCrypto::algorithmStrength(8));
        self::assertSame('deprecated', DnssecCrypto::algorithmStrength(7));
        self::assertSame('insecure', DnssecCrypto::algorithmStrength(1));
        self::assertSame('unknown', DnssecCrypto::algorithmStrength(99));
        self::assertStringContainsString('ECDSAP256SHA256', DnssecCrypto::algorithmName(13));
    }

    // ---- DNSSEC-Befunde: Records vs. Plausibilität vs. Validierung -------------------------------------------

    private function dnssecFake(bool $withDs, bool $matchingDs, bool $ad, bool $failure = false): FakeDns
    {
        $fx = $this->fixture();
        $fake = new FakeDns();
        $dnskeys = [];
        $rrs = [];
        $raw = json_decode((string) file_get_contents(__DIR__ . '/../fixtures/dnssec_cloudflare.json'), true);
        foreach ($raw['DNSKEY'] as $r) {
            $dnskeys[] = [$r['type'], $r['data']];
        }
        $fake->set('example.test', 'DNSKEY', $dnskeys, 0, $ad);
        if ($withDs) {
            $ds = $matchingDs ? $raw['DS'][0]['data'] : '12345 13 2 ' . str_repeat('AB', 32);
            $fake->set('example.test', 'DS', [['DS', $matchingDs ? $this->dsFor('example.test', $fx) : $ds]], 0, $ad);
        }
        $fake->set('example.test', 'SOA', [['SOA', 'ns1.example.test. h.example.test. 1 2 3 4 5']], $failure ? 2 : 0, $ad);
        return $fake;
    }

    /** DS, das zum KSK des Fixtures passt – für die Zone example.test berechnet (Owner fließt in den Digest ein). */
    private function dsFor(string $zone, array $fx): string
    {
        foreach ($fx['keys'] as $k) {
            if (($k['flags'] & 1) === 1) {
                $rd = DnssecCrypto::dnskeyRdata($k['flags'], $k['protocol'], $k['algorithm'], $k['key']);
                return DnssecCrypto::keyTag($rd) . ' ' . $k['algorithm'] . ' 2 ' . strtoupper((string) DnssecCrypto::dsDigest($zone, $rd, 2));
            }
        }
        return '';
    }

    public function testUnsignedZoneIsInformationNotAVulnerability(): void
    {
        $svc = new DnssecService((new FakeDns())->client(), new RawDnsClient());
        $a = $svc->analyze('example.test', false);
        self::assertSame('unsigned', $a['state']);
        self::assertSame('none', $a['validation']['level']);
        self::assertSame([], FindingsEngine::forDnssec('example.test', $a), 'Unsigniert ist kein Finding');
    }

    public function testDsWithoutMatchingDnskeyIsBrokenChain(): void
    {
        $a = (new DnssecService($this->dnssecFake(true, false, false)->client(), new RawDnsClient()))->analyze('example.test', false);
        self::assertSame('broken', $a['state']);
        self::assertFalse($a['ds'][0]['matches_dnskey']);
        $f = FindingsEngine::forDnssec('example.test', $a);
        self::assertContains('dnssec.ds_mismatch', array_column($f, 'rule_id'));
    }

    public function testDsWithoutDnskeyAndDnskeyWithoutDs(): void
    {
        $fake = (new FakeDns())->set('example.test', 'DS', [['DS', '2371 13 2 ' . str_repeat('AB', 32)]]);
        $a = (new DnssecService($fake->client(), new RawDnsClient()))->analyze('example.test', false);
        self::assertSame('broken', $a['state']);
        self::assertContains('dnssec.ds_without_dnskey', array_column(FindingsEngine::forDnssec('example.test', $a), 'rule_id'));

        $a = (new DnssecService($this->dnssecFake(false, false, false)->client(), new RawDnsClient()))->analyze('example.test', false);
        self::assertSame('dnskey_only', $a['state']);
        self::assertContains('dnssec.no_ds', array_column(FindingsEngine::forDnssec('example.test', $a), 'rule_id'));
    }

    public function testConsistentChainDistinguishesRecordsLocalCryptoAndResolverValidation(): void
    {
        // DS passt (Owner example.test), aber die RRSIG des Fixtures gilt für cloudflare.com → lokale Prüfung schlägt fehl
        $a = (new DnssecService($this->dnssecFake(true, true, true)->client(), new RawDnsClient()))->analyze('example.test', false);
        self::assertTrue($a['ds'][0]['matches_dnskey']);
        self::assertSame('signed', $a['state']);
        $sigs = array_filter($a['rrsig'], static fn($s) => $s['crypto'] !== null);
        self::assertNotEmpty($sigs);
        self::assertFalse(array_values($sigs)[0]['crypto']['valid'], 'Signatur gehört zu einer anderen Zone und darf lokal nicht validieren');
        self::assertContains('dnssec.rrsig_invalid', array_column(FindingsEngine::forDnssec('example.test', $a), 'rule_id'));
        // Es wird keine lokale Validierung behauptet
        self::assertNotSame('partial_local', $a['validation']['level']);
        self::assertNotSame('partial_local_plus_resolver', $a['validation']['level']);
    }

    public function testValidationFailureDetectedViaCheckingDisabledComparison(): void
    {
        $fake = $this->dnssecFake(true, false, false, true);
        $client = new \DomainScope\Services\DNS\DohClient(function (string $url) use ($fake): array {
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            // Normale SOA-Abfrage → SERVFAIL, mit cd=1 → NOERROR (typisches Bild einer fehlschlagenden Validierung)
            if (($q['type'] ?? '') === 'SOA') {
                $cd = isset($q['cd']);
                return ['body' => json_encode(['Status' => $cd ? 0 : 2, 'Answer' => $cd ? [['name' => 'example.test.', 'type' => 6, 'TTL' => 60, 'data' => 'ns1.example.test. h.example.test. 1 2 3 4 5']] : []]), 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 4];
            }
            return ['body' => json_encode(['Status' => 0]), 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 4];
        });
        $a = (new DnssecService($client, new RawDnsClient()))->analyze('example.test', false);
        self::assertSame('broken', $a['state']);
        self::assertTrue($a['resolvers']['cloudflare']['validation_failure']);
        $f = FindingsEngine::forDnssec('example.test', $a);
        $rules = array_column($f, 'rule_id');
        self::assertContains('dnssec.validation_failure', $rules);
        self::assertSame('critical', $f[array_search('dnssec.validation_failure', $rules, true)]['severity']);
    }

    public function testDelegationChecksWithMockedAuthoritativeServers(): void
    {
        \DomainScope\Services\Http\HostResolver::$override = static fn(string $h) => match (true) {
            str_starts_with($h, 'ns1.') => ['93.184.216.1'], str_starts_with($h, 'ns2.') => ['93.184.216.2'],
            default => ['93.184.216.9'],
        };
        $fake = (new FakeDns())
            ->set('example.test', 'NS', [['NS', 'ns1.example.test.'], ['NS', 'ns2.example.test.']])
            ->set('test', 'NS', [['NS', 'a.nic.test.']]);
        RawDnsClient::$transport = static function (string $ip, string $packet, bool $tcp): ?string {
            $id = unpack('n', substr($packet, 0, 2))[1];
            $q = substr($packet, 12);
            $qEnd = strpos($q, "\x00") + 5;
            $question = substr($q, 0, $qEnd);
            $qtype = unpack('n', substr($question, -4, 2))[1];
            $hdr = static fn(int $flags, int $an, int $ns = 0) => pack('nnnnnn', $id, $flags, 1, $an, $ns, 0);
            if ($ip === '93.184.216.2') {
                return null; // ns2 antwortet nicht
            }
            if ($ip === '93.184.216.9') { // Parent: Delegation (Authority-Section)
                $name = RawDnsClient::nameToWire('example.test');
                $ns1 = RawDnsClient::nameToWire('ns1.example.test');
                $rr = "\xC0\x0C" . pack('nnNn', 2, 1, 3600, strlen($ns1)) . $ns1;
                return $hdr(0x8000, 0, 1) . $question . $rr;
            }
            // ns1: nicht autoritativ (kein AA), SOA-Antwort
            if ($qtype === 6) {
                $rd = RawDnsClient::nameToWire('ns1.example.test') . RawDnsClient::nameToWire('h.example.test') . pack('NNNNN', 7, 1, 2, 3, 4);
                return $hdr(0x8000, 1) . $question . "\xC0\x0C" . pack('nnNn', 6, 1, 60, strlen($rd)) . $rd;
            }
            return $hdr(0x8000, 0) . $question;
        };
        try {
            $a = (new DnssecService($fake->client(), new RawDnsClient()))->analyze('example.test', true);
        } finally {
            RawDnsClient::$transport = null;
            \DomainScope\Services\Http\HostResolver::$override = null;
        }
        $codes = array_column($a['delegation']['issues'], 'code');
        self::assertContains('delegation.lame', $codes, 'ns1 antwortet ohne AA-Flag');
        self::assertContains('delegation.ns_unreachable', $codes, 'ns2 antwortet nicht');
        self::assertContains('delegation.ns_mismatch', $codes, 'Parent kennt nur ns1, Zone nennt ns1+ns2');
        self::assertSame('test', $a['delegation']['parent'] === 'test' ? 'test' : $a['delegation']['parent']);
        self::assertSame(['ns1.example.test'], $a['delegation']['parent_view']['ns']);
    }
}

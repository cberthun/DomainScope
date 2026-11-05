<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Services\Http\{HostResolver, SafeHttp};
use DomainScope\Services\RDAP\{RdapBootstrap, RdapClient};
use DomainScope\Services\WHOIS\WhoisClient;
use PHPUnit\Framework\TestCase;

final class RegistrationTest extends TestCase
{
    private string $dir;
    /** @var string[] */
    private array $requested = [];

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/ds-rdap-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        file_put_contents($this->dir . '/rdap-dns.json', json_encode(['services' => [
            [['com', 'net'], ['https://rdap.verisign.example/com/v1/']],
            [['org'], ['http://rdap.org-registry.example/', 'https://rdap.org-registry.example/']],
        ]]));
        file_put_contents($this->dir . '/rdap-ipv4.json', json_encode(['services' => [
            [['192.0.0.0/8'], ['https://rdap.arin.example/']], [['192.0.2.0/24'], ['https://rdap.specific.example/']],
        ]]));
        file_put_contents($this->dir . '/rdap-asn.json', json_encode(['services' => [[['64496-64511', '65000'], ['https://rdap.asn.example/']]]]));
        RdapBootstrap::$dataDir = $this->dir;
        RdapBootstrap::$allowRefresh = false;
        RdapBootstrap::reset();
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
        RdapBootstrap::$dataDir = null;
        RdapBootstrap::$allowRefresh = true;
        RdapBootstrap::reset();
        HostResolver::$override = null;
        SafeHttp::$transport = null;
    }

    /** @param array<string,array{0:int,1:array|string}> $routes URL-Teil => [Status, Body] */
    private function mockHttp(array $routes): void
    {
        SafeHttp::$transport = function (array $hop) use ($routes): array {
            $this->requested[] = $hop['url'];
            foreach ($routes as $needle => [$status, $body, $headers]) {
                if (str_contains($hop['url'], $needle)) {
                    return ['ok' => $status < 400, 'status' => $status, 'headers' => $headers ?? [], 'body' => is_array($body) ? json_encode($body) : $body,
                        'final_url' => $hop['url'], 'ip' => $hop['ip'], 'redirects' => [], 'ms' => 7, 'error' => null, 'error_code' => null, 'truncated' => false];
                }
            }
            return ['ok' => false, 'status' => 0, 'headers' => [], 'body' => '', 'final_url' => $hop['url'], 'ip' => null, 'redirects' => [], 'ms' => 1, 'error' => 'Connection refused', 'error_code' => 'connect', 'truncated' => false];
        };
    }

    // ---- Bootstrap ------------------------------------------------------------------------------------

    public function testBootstrapSelectsEndpointPerTldAndPrefersHttps(): void
    {
        self::assertSame('https://rdap.verisign.example/com/v1/', RdapBootstrap::dnsService('COM'));
        self::assertSame('https://rdap.org-registry.example/', RdapBootstrap::dnsService('org'));
        self::assertNull(RdapBootstrap::dnsService('unbekannt'));
        self::assertSame('https://rdap.specific.example/', RdapBootstrap::ipService('192.0.2.5'), 'spezifischstes Präfix gewinnt');
        self::assertSame('https://rdap.arin.example/', RdapBootstrap::ipService('192.1.1.1'));
        self::assertNull(RdapBootstrap::ipService('203.0.113.1'));
        self::assertSame('https://rdap.asn.example/', RdapBootstrap::asnService(64500));
        self::assertSame('https://rdap.asn.example/', RdapBootstrap::asnService(65000));
        self::assertNull(RdapBootstrap::asnService(1));
    }

    public function testSupplementalEndpointIsOnlyUsedWhenIanaHasNoEntry(): void
    {
        self::assertSame('https://rdap.denic.de/', RdapBootstrap::dnsService('de'));
    }

    // ---- Domainabfrage ------------------------------------------------------------------------------

    private function verisignResponse(): array
    {
        return [
            'ldhName' => 'EXAMPLE.COM', 'status' => ['client delete prohibited', 'client transfer prohibited'],
            'events' => [
                ['eventAction' => 'registration', 'eventDate' => '1995-08-14T04:00:00Z'],
                ['eventAction' => 'expiration', 'eventDate' => '2027-08-13T04:00:00Z'],
                ['eventAction' => 'last changed', 'eventDate' => '2026-01-16T18:26:12Z'],
            ],
            'nameservers' => [['ldhName' => 'B.IANA-SERVERS.NET'], ['ldhName' => 'A.IANA-SERVERS.NET']],
            'secureDNS' => ['delegationSigned' => true, 'dsData' => [['keyTag' => 370, 'algorithm' => 13, 'digestType' => 2, 'digest' => 'ABCD']]],
            'entities' => [[
                'roles' => ['registrar'], 'vcardArray' => ['vcard', [['version', [], 'text', '4.0'], ['fn', [], 'text', 'Example Registrar, Inc.']]],
                'publicIds' => [['type' => 'IANA Registrar ID', 'identifier' => '376']],
            ], [
                'roles' => ['registrant'], 'vcardArray' => ['vcard', [['fn', [], 'text', 'REDACTED FOR PRIVACY']]],
            ]],
            'links' => [['rel' => 'related', 'href' => 'https://rdap.registrar.example/domain/EXAMPLE.COM', 'type' => 'application/rdap+json']],
        ];
    }

    public function testDomainResponseIsNormalizedAndRegistrarRdapIsFollowed(): void
    {
        $registrar = ['ldhName' => 'EXAMPLE.COM', 'status' => ['active'], 'events' => [['eventAction' => 'expiration', 'eventDate' => '2027-08-20T00:00:00Z']]];
        $this->mockHttp(['rdap.verisign.example' => [200, $this->verisignResponse(), []], 'rdap.registrar.example' => [200, $registrar, []]]);
        $r = (new RdapClient())->domain('example.com');
        self::assertTrue($r['ok']);
        self::assertSame('rdap', $r['source']);
        self::assertSame('Example Registrar, Inc.', $r['registrar']);
        self::assertSame('376', $r['registrar_iana_id']);
        self::assertSame('1995-08-14 04:00:00', $r['registered_at']);
        self::assertSame('2027-08-13 04:00:00', $r['expires_at'], 'Registry-Wert hat Vorrang');
        self::assertSame('2026-01-16 18:26:12', $r['changed_at']);
        self::assertSame(['a.iana-servers.net', 'b.iana-servers.net'], $r['nameservers']);
        self::assertTrue($r['dnssec_signed']);
        self::assertSame(['370 13 2 ABCD'], $r['ds_data']);
        self::assertContains('active', $r['statuses']);
        self::assertContains('client transfer prohibited', $r['statuses']);
        self::assertCount(2, $this->requested, 'Registry + Registrar');
        $redacted = array_values(array_filter($r['entities'], static fn($e) => in_array('registrant', $e['roles'], true)));
        self::assertTrue($redacted[0]['redacted'], 'Redigierte Registrant-Daten werden erkannt');
    }

    public function testUnsupportedTldNotFoundAndRateLimit(): void
    {
        $this->mockHttp([]);
        $r = (new RdapClient())->domain('example.zzz');
        self::assertFalse($r['ok']);
        self::assertSame('unsupported_tld', $r['error_code']);

        $this->mockHttp(['domain/' => [404, '{}', []]]);
        $r = (new RdapClient())->domain('missing.com');
        self::assertSame('not_found', $r['error_code']);

        $this->mockHttp(['domain/' => [429, '', ['retry-after' => '120']]]);
        $r = (new RdapClient())->domain('busy.com');
        self::assertSame('rate_limited', $r['error_code']);
        self::assertStringContainsString('120', $r['error']);

        $this->mockHttp(['domain/' => [200, 'kein json', []]]);
        self::assertSame('invalid_response', (new RdapClient())->domain('weird.com')['error_code']);

        $this->mockHttp(['domain/' => [500, '', []]]);
        self::assertSame('http_error', (new RdapClient())->domain('down.com')['error_code']);

        $this->mockHttp([]); // Verbindung schlägt fehl
        self::assertSame('unreachable', (new RdapClient())->domain('example.com')['error_code']);
    }

    public function testRedactedAndMissingFieldsDoNotBreakParsing(): void
    {
        $this->mockHttp(['domain/' => [200, ['ldhName' => 'minimal.org'], []]]);
        $r = (new RdapClient())->domain('minimal.org');
        self::assertTrue($r['ok']);
        self::assertNull($r['registrar']);
        self::assertNull($r['expires_at']);
        self::assertNull($r['dnssec_signed']);
        self::assertSame([], $r['nameservers']);
    }

    public function testIpAndAsnLookups(): void
    {
        $this->mockHttp([
            'rdap.specific.example/ip/192.0.2.5' => [200, ['name' => 'TEST-NET', 'handle' => 'NET-1', 'country' => 'US', 'startAddress' => '192.0.2.0', 'endAddress' => '192.0.2.255',
                'cidr0_cidrs' => [['v4prefix' => '192.0.2.0', 'length' => 24]], 'entities' => [['roles' => ['registrant'], 'vcardArray' => ['vcard', [['fn', [], 'text', 'Beispiel Org']]]]]], []],
            'rdap.asn.example/autnum/64500' => [200, ['name' => 'EXAMPLE-AS', 'country' => 'DE'], []],
        ]);
        $ip = (new RdapClient())->ip('192.0.2.5');
        self::assertSame('192.0.2.0/24', $ip['cidr']);
        self::assertSame('TEST-NET', $ip['name']);
        self::assertSame(['Beispiel Org'], $ip['registrant']);
        self::assertSame('EXAMPLE-AS', (new RdapClient())->asn(64500)['name']);
        self::assertFalse((new RdapClient())->asn(7)['ok']);
    }

    // ---- WHOIS ----------------------------------------------------------------------------------------

    public function testWhoisFallbackParsesCommonFields(): void
    {
        WhoisClient::$transport = static function (string $server, string $query): string {
            if ($server === 'whois.iana.org') {
                return "refer: whois.nic.test\nwhois: whois.nic.test\n";
            }
            return "Domain Name: EXAMPLE.TEST\nRegistrar: Test Registrar GmbH\nCreation Date: 2010-05-01T10:00:00Z\nRegistry Expiry Date: 2027-05-01T10:00:00Z\n"
                . "Updated Date: 2026-04-01T08:00:00Z\nDomain Status: clientTransferProhibited https://icann.org/epp\nName Server: NS2.EXAMPLE.TEST\nName Server: ns1.example.test.\nDNSSEC: signedDelegation\n";
        };
        try {
            $r = (new WhoisClient())->domain('example.test');
            self::assertTrue($r['ok']);
            self::assertSame('whois', $r['source']);
            self::assertSame('Test Registrar GmbH', $r['registrar']);
            self::assertSame('2027-05-01 10:00:00', $r['expires_at']);
            self::assertSame(['clientTransferProhibited'], $r['statuses']);
            self::assertSame(['ns1.example.test', 'ns2.example.test'], $r['nameservers']);
            self::assertNotEmpty($r['notes'], 'Heuristische Auswertung wird gekennzeichnet');
        } finally {
            WhoisClient::$transport = null;
        }
    }

    public function testWhoisNotFoundAndUnsupportedTld(): void
    {
        WhoisClient::$transport = static fn(string $s, string $q) => $s === 'whois.iana.org' ? "whois: whois.nic.test\n" : "No match for domain \"NOPE.TEST\"\n";
        try {
            self::assertSame('not_found', (new WhoisClient())->domain('nope.test')['error_code']);
        } finally {
            WhoisClient::$transport = null;
        }
        WhoisClient::$transport = static fn(string $s, string $q) => "% IANA WHOIS server\nstatus: ACTIVE\n";
        try {
            self::assertSame('unsupported_tld', (new WhoisClient())->domain('x.nowhois')['error_code']);
        } finally {
            WhoisClient::$transport = null;
        }
        WhoisClient::$transport = static fn() => null;
        try {
            self::assertSame('unreachable', (new WhoisClient())->domain('x.test')['error_code']);
        } finally {
            WhoisClient::$transport = null;
        }
    }
}

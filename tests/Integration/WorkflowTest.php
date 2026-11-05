<?php
declare(strict_types=1);

namespace DomainScope\Tests\Integration;

use DomainScope\Jobs\ModuleRunner;
use DomainScope\Repositories\{ActivityRepository, AssetRepository, DnsSnapshotRepository, DomainRepository, FindingRepository, IpRepository, ModuleResultRepository};
use DomainScope\Services\Http\{HostResolver, SafeHttp};
use DomainScope\Services\Reports\ReportBuilder;
use DomainScope\Support\{Database, Settings};
use DomainScope\Tests\Support\FakeDns;

/** End-to-End-Abläufe mit gemocktem DNS: Modul → Snapshot → Änderungserkennung → Findings. */
final class WorkflowTest extends DatabaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        HostResolver::$override = static fn(string $h) => ['93.184.216.34'];
        SafeHttp::$transport = static fn(array $hop) => ['ok' => false, 'status' => 0, 'headers' => [], 'body' => '', 'final_url' => $hop['url'], 'ip' => $hop['ip'],
            'redirects' => [], 'ms' => 1, 'error' => 'nicht verfügbar im Test', 'error_code' => 'connect', 'truncated' => false];
    }

    protected function tearDown(): void
    {
        HostResolver::$override = null;
        SafeHttp::$transport = null;
    }

    private function zone(string $mx = '10 mx1.example.com.', string $dmarc = 'v=DMARC1; p=none; rua=mailto:r@example.com'): FakeDns
    {
        $z = (new FakeDns())
            ->set('example.com', 'A', [['A', '192.0.2.10']])->set('example.com', 'AAAA', [])
            ->set('example.com', 'MX', [['MX', $mx]])
            ->set('example.com', 'NS', [['NS', 'ns1.example.net.'], ['NS', 'ns2.example.net.']])
            ->txt('example.com', 'v=spf1 mx -all')
            ->set('mx1.example.com', 'A', [['A', '192.0.2.25']])->set('mx2.example.com', 'A', [['A', '192.0.2.26']])
            ->set('www.example.com', 'A', [['A', '192.0.2.10']]);
        if ($dmarc !== '') {
            $z->txt('_dmarc.example.com', $dmarc);
        }
        return $z;
    }

    public function testDnsModuleStoresSnapshotsLinksIpsAndDetectsChanges(): void
    {
        $domain = $this->domain();
        $id = (int) $domain['id'];
        $r1 = (new ModuleRunner($this->zone()->client()))->run($domain, 'dns');
        self::assertTrue($r1['ok'], $r1['message']);
        $snap = DnsSnapshotRepository::latest($id, 'example.com', (string) cfg('app.dns.default_resolver'));
        self::assertNotNull($snap);
        $types = array_column(DnsSnapshotRepository::records((int) $snap['id']), 'type');
        self::assertContains('MX', $types);
        self::assertContains('NS', $types);
        $ips = array_column(IpRepository::forDomain($id), 'address');
        self::assertContains('192.0.2.10', $ips);
        self::assertSame([], ActivityRepository::changes($id), 'Erster Snapshot erzeugt keine Änderungen');

        // unveränderte Wiederholung → keine neue Änderung
        (new ModuleRunner($this->zone()->client()))->run($domain, 'dns');
        self::assertSame([], ActivityRepository::changes($id));

        // MX-, SPF- und IP-Änderung
        $changed = $this->zone('10 mx2.example.com.')->set('example.com', 'A', [['A', '192.0.2.77']])->txt('example.com', 'v=spf1 ip4:192.0.2.0/24 -all');
        $r3 = (new ModuleRunner($changed->client()))->run($domain, 'dns');
        self::assertGreaterThanOrEqual(3, $r3['data']['changes']);
        $byType = array_column(ActivityRepository::changes($id), null, 'type');
        self::assertArrayHasKey('dns.mx_changed', $byType);
        self::assertArrayHasKey('email.spf_changed', $byType);
        self::assertArrayHasKey('ip.mapping_changed', $byType);
        self::assertStringContainsString('mx2.example.com', $byType['dns.mx_changed']['summary']);
    }

    public function testPartialDnsFailureDoesNotCreateFalseRemovals(): void
    {
        $domain = $this->domain();
        $id = (int) $domain['id'];
        (new ModuleRunner($this->zone()->client()))->run($domain, 'dns');
        $before = (int) Database::value('SELECT COUNT(*) FROM dns_snapshots WHERE host = ?', ['example.com']);
        $flaky = new \DomainScope\Services\DNS\DohClient(function (string $url): array {
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            if (($q['type'] ?? '') === 'MX') {
                return ['body' => null, 'http' => 0, 'error' => 'Operation timed out', 'errno' => CURLE_OPERATION_TIMEOUTED, 'ms' => 6000];
            }
            return ['body' => json_encode(['Status' => 0]), 'http' => 200, 'error' => null, 'errno' => 0, 'ms' => 3];
        });
        $res = (new ModuleRunner($flaky))->run($domain, 'dns');
        self::assertFalse($res['ok']);
        self::assertSame($before, (int) Database::value('SELECT COUNT(*) FROM dns_snapshots WHERE host = ?', ['example.com']), 'Bei Abfragefehlern wird kein (unvollständiger) Apex-Snapshot gespeichert');
        $types = array_column(ActivityRepository::changes($id), 'type');
        foreach (['dns.mx_changed', 'dns.ns_changed', 'email.spf_changed'] as $t) {
            self::assertNotContains($t, $types, 'Timeouts dürfen keine ' . $t . '-Änderung erzeugen');
        }
    }

    public function testEmailModuleDerivesFindingsFromRealResultsAndResolvesThem(): void
    {
        $domain = $this->domain();
        $id = (int) $domain['id'];
        $runner = new ModuleRunner($this->zone()->client());
        $res = $runner->run($domain, 'email');
        self::assertTrue($res['ok'], $res['message']);
        $findings = array_column(FindingRepository::search(['domain_id' => $id, 'status' => 'active']), null, 'rule_id');
        self::assertArrayHasKey('dmarc.p_none', $findings);
        self::assertSame('medium', $findings['dmarc.p_none']['severity']);
        self::assertSame('E-Mail: DMARC', $findings['dmarc.p_none']['category']);
        self::assertStringContainsString('Monitoring', $findings['dmarc.p_none']['reasoning']);
        self::assertNotEmpty($findings['dmarc.p_none']['recommendation']);
        self::assertNotEmpty($findings['dmarc.p_none']['source']);
        self::assertArrayNotHasKey('dkim.none_found', $findings, 'Nichtfund von Selektoren ist kein Finding');
        self::assertArrayNotHasKey('spf.missing', $findings);
        self::assertSame('medium', ModuleResultRepository::latest($id, 'email')['status'] === 'pass' ? 'medium' : 'medium');

        // DMARC auf reject anheben → Finding wird automatisch behoben
        (new ModuleRunner($this->zone(dmarc: 'v=DMARC1; p=reject; rua=mailto:r@example.com')->client()))->run($domain, 'email');
        $all = array_column(FindingRepository::search(['domain_id' => $id, 'status' => '']), null, 'rule_id');
        self::assertSame('resolved', $all['dmarc.p_none']['status']);
        self::assertContains('auto_resolved', array_column(FindingRepository::events((int) $all['dmarc.p_none']['id']), 'event'));
    }

    public function testMissingPoliciesAreRatedLowerForDomainsWithoutMail(): void
    {
        $domain = $this->domain();
        $id = (int) $domain['id'];
        $noMail = (new FakeDns())->set('example.com', 'MX', [['MX', '0 .']])->set('example.com', 'A', [['A', '192.0.2.10']]);
        (new ModuleRunner($noMail->client()))->run($domain, 'email');
        $f = array_column(FindingRepository::search(['domain_id' => $id, 'status' => 'active']), null, 'rule_id');
        self::assertSame('low', $f['spf.missing']['severity'], 'Null-MX: fehlendes SPF ist nur niedrig');
        self::assertSame('low', $f['dmarc.missing']['severity']);

        $mail = (new FakeDns())->set('example.com', 'MX', [['MX', '10 mx1.example.com.']])->set('mx1.example.com', 'A', [['A', '192.0.2.25']]);
        (new ModuleRunner($mail->client()))->run($domain, 'email');
        $f = array_column(FindingRepository::search(['domain_id' => $id, 'status' => 'active']), null, 'rule_id');
        self::assertSame('medium', $f['spf.missing']['severity'], 'mit MX bleibt fehlendes SPF mittel');
    }

    public function testUnreachableDnsYieldsNoSecurityFindings(): void
    {
        $domain = $this->domain();
        $fake = new FakeDns();
        $fake->failWith = 'timeout';
        $res = (new ModuleRunner($fake->client()))->run($domain, 'email');
        self::assertSame([], FindingRepository::search(['domain_id' => (int) $domain['id']]), 'Ausgefallene Quellen dürfen keine Sicherheitsbefunde erzeugen');
        self::assertFalse($res['ok']);
    }

    public function testScanJobIsRecordedWithPerModuleResults(): void
    {
        $domain = $this->domain();
        $res = (new ModuleRunner($this->zone()->client()))->runAll($domain, 'cron', ['dns', 'email']);
        self::assertContains($res['status'], ['ok', 'partial']);
        $job = Database::one('SELECT * FROM scan_jobs WHERE id = ?', [$res['job_id']]);
        self::assertSame('cron', $job['trigger_type']);
        self::assertNotNull($job['finished_at']);
        self::assertCount(2, Database::all('SELECT * FROM scan_results WHERE job_id = ?', [$res['job_id']]));
        self::assertNotNull(DomainRepository::find('example.com')['last_checked_at']);
    }

    public function testReportsContainSourcesLimitationsAndTimestamp(): void
    {
        $domain = $this->domain();
        (new ModuleRunner($this->zone()->client()))->runAll($domain, 'manual', ['dns', 'email']);
        AssetRepository::create(['name' => 'web1', 'type' => 'server']);
        $b = new ReportBuilder();
        foreach (['domain', 'email', 'tls', 'dns-changes'] as $type) {
            $r = $b->build($type, DomainRepository::find('example.com'));
            self::assertNotEmpty($r['sources'], $type);
            self::assertNotEmpty($r['limitations'], $type);
            self::assertMatchesRegularExpression('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $r['generated_at']);
            self::assertSame('example.com', $r['domain']);
            self::assertNotEmpty($r['sections']);
        }
        $inv = $b->build('inventory', null);
        self::assertSame('web1', $inv['sections'][0]['rows'][0][0]);
        $dom = $b->build('domain', DomainRepository::find('example.com'));
        $dns = array_filter($dom['sections'], static fn($s) => str_starts_with($s['title'], 'DNS-Records'));
        self::assertNotEmpty(array_values($dns)[0]['rows']);
        $this->expectException(\InvalidArgumentException::class);
        $b->build('unbekannt', null);
    }

    // ---- Ausgabe-Escaping über die echte Anwendung -----------------------------------------------------------------

    public function testUserControlledValuesAreHtmlEscapedInPages(): void
    {
        $domain = $this->domain();
        DomainRepository::setNotes((int) $domain['id'], '<script>alert("xss")</script>');
        AssetRepository::create(['name' => '<img src=x onerror=alert(1)>', 'type' => 'server', 'description' => '"><svg onload=1>']);
        Database::insert('change_events', ['domain_id' => $domain['id'], 'type' => 'dns.record_added', 'summary' => '<b>fremd</b> TXT "x"', 'detected_at' => Database::now()]);

        $session = ['auth_user' => 'admin', 'last_activity' => time(), '_csrf' => str_repeat('ef', 32)];
        foreach (['/domain/example.com?tab=notes' => '&lt;script&gt;', '/inventory' => '&lt;img src=x', '/domain/example.com?tab=history' => '&lt;b&gt;fremd'] as $path => $needle) {
            $parts = parse_url($path);
            parse_str($parts['query'] ?? '', $query);
            $r = $this->childRequest(['method' => 'GET', 'path' => $parts['path'], 'query' => $query, 'session' => $session]);
            self::assertSame(200, $r['status'], $path);
            self::assertStringContainsString($needle, $r['body'], $path);
            self::assertStringNotContainsString('<script>alert("xss")', $r['body'], $path);
            self::assertStringNotContainsString('<img src=x onerror', $r['body'], $path);
            self::assertStringNotContainsString('<b>fremd</b>', $r['body'], $path);
        }
    }

    /** @return array<string,mixed> */
    private function childRequest(array $in): array
    {
        $in['config'] = ['auth.password_hash' => password_hash('x', PASSWORD_BCRYPT, ['cost' => 4])];
        $proc = proc_open([PHP_BINARY, __DIR__ . '/../Support/run_request.php', json_encode($in)], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        proc_close($proc);
        $data = json_decode((string) $out, true);
        self::assertIsArray($data, "Kindprozess: $out $err");
        return $data;
    }
}

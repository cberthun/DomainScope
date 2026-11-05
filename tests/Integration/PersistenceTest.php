<?php
declare(strict_types=1);

namespace DomainScope\Tests\Integration;

use DomainScope\Repositories\{ActivityRepository, AssetRepository, DnsSnapshotRepository, DomainRepository, FindingRepository, ModuleResultRepository, SubdomainRepository};
use DomainScope\Security\Auth;
use DomainScope\Support\{Database, Migrator, Request, Settings};

final class PersistenceTest extends DatabaseTestCase
{
    // ---- Schema & Datenbankzugriff --------------------------------------------------------------------

    public function testMigrationsAreIdempotentAndCreateExpectedTables(): void
    {
        $m = new Migrator();
        self::assertSame(0, $m->migrate(), 'Zweiter Lauf wendet nichts erneut an');
        self::assertTrue(array_reduce($m->status(), static fn($c, $s) => $c && $s['applied'], true));
        $tables = array_map(static fn($r) => array_values($r)[0], Database::all('SHOW TABLES'));
        foreach (['domains', 'assets', 'asset_relationships', 'dns_snapshots', 'dns_records', 'registration_snapshots', 'subdomains', 'ip_addresses',
            'certificates', 'findings', 'scan_jobs', 'scan_results', 'application_settings', 'module_results', 'tls_checks', 'change_events'] as $t) {
            self::assertContains($t, $tables, $t);
        }
    }

    public function testForeignKeysCascadeOnDomainDeletion(): void
    {
        $d = $this->domain();
        $id = (int) $d['id'];
        DnsSnapshotRepository::store($id, 'example.com', 'cloudflare', [['name' => 'example.com', 'type' => 'A', 'ttl' => 60, 'data' => '192.0.2.1']]);
        FindingRepository::reconcile($id, 'email', [$this->draft('x.rule', 'high')]);
        self::assertSame(1, (int) Database::value('SELECT COUNT(*) FROM dns_records'));
        DomainRepository::delete($id);
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM dns_snapshots'));
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM dns_records'));
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM findings'));
    }

    public function testPreparedStatementsNeutralizeInjectionAttempts(): void
    {
        $evil = "x'); DROP TABLE domains; --";
        Database::insert('assets', ['name' => $evil, 'type' => 'server', 'environment' => 'production', 'tags' => '', 'created_at' => Database::now(), 'updated_at' => Database::now()]);
        $row = Database::one('SELECT name FROM assets WHERE name = ?', [$evil]);
        self::assertSame($evil, $row['name']);
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM domains'));
        self::assertSame(1, (int) Database::value('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?', ['domains']), 'Tabelle existiert weiterhin');
        // LIKE-Platzhalter in Suchbegriffen werden maskiert
        self::assertSame([], AssetRepository::all(['q' => '%']), '"%" ist kein Wildcard-Suchbegriff');
    }

    public function testTransactionsRollBackOnError(): void
    {
        try {
            Database::transaction(function (): void {
                Database::insert('domains', ['name' => 'rolled.example', 'unicode_name' => 'rolled.example', 'public_suffix' => 'example', 'tld' => 'example', 'created_at' => Database::now()]);
                throw new \RuntimeException('Abbruch');
            });
            self::fail('Exception erwartet');
        } catch (\RuntimeException) {
        }
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM domains'));
        $v = Database::transaction(static fn() => Database::transaction(static fn() => 42));
        self::assertSame(42, $v, 'verschachtelte Transaktionen sind erlaubt');
    }

    public function testUniqueConstraintsPreventDuplicates(): void
    {
        $a = $this->domain('example.com');
        $b = $this->domain('www.EXAMPLE.com');
        self::assertSame($a['id'], $b['id'], 'Subdomain/Schreibweise führt zur selben registrierbaren Domain');
        self::assertCount(1, DomainRepository::all());
        $this->expectException(\PDOException::class);
        Database::insert('domains', ['name' => 'example.com', 'unicode_name' => 'example.com', 'public_suffix' => 'com', 'tld' => 'com', 'created_at' => Database::now()]);
    }

    public function testSettingsRoundTripAndThresholdParsing(): void
    {
        self::assertSame([30, 14, 7], Settings::days('cert_warn_days'), 'Default');
        Settings::set('cert_warn_days', '7,60,14,14,x,0');
        self::assertSame([60, 14, 7], Settings::days('cert_warn_days'), 'absteigend, eindeutig, ungültige Werte verworfen');
        Settings::set('whois_fallback', '0');
        self::assertFalse(Settings::bool('whois_fallback'));
    }

    // ---- Snapshots -----------------------------------------------------------------------------------

    private function rec(string $type, string $data, string $name = 'example.com', int $ttl = 300): array
    {
        return ['name' => $name, 'type' => $type, 'ttl' => $ttl, 'data' => $data];
    }

    public function testSnapshotsAreOnlyStoredOnChangeAndDiffIgnoresTtl(): void
    {
        $id = (int) $this->domain()['id'];
        $base = [$this->rec('A', '192.0.2.1'), $this->rec('MX', '10 mx.example.com')];
        $s1 = DnsSnapshotRepository::store($id, 'example.com', 'cloudflare', $base);
        self::assertTrue($s1['changed']);
        self::assertNull($s1['previous_id']);

        $s2 = DnsSnapshotRepository::store($id, 'example.com', 'cloudflare', [$this->rec('MX', '10 mx.example.com', ttl: 5), $this->rec('A', '192.0.2.1', ttl: 9)]);
        self::assertFalse($s2['changed'], 'gleiche Records (andere Reihenfolge/TTL) = unverändert');
        self::assertSame($s1['snapshot_id'], $s2['snapshot_id']);
        self::assertSame(1, (int) Database::value('SELECT COUNT(*) FROM dns_snapshots'));

        $s3 = DnsSnapshotRepository::store($id, 'example.com', 'cloudflare', [$this->rec('A', '192.0.2.99'), $this->rec('MX', '10 mx.example.com'), $this->rec('TXT', 'v=spf1 -all')]);
        self::assertTrue($s3['changed']);
        self::assertSame($s1['snapshot_id'], $s3['previous_id']);
        $added = array_column($s3['added'], 'data');
        sort($added);
        self::assertSame(['192.0.2.99', 'v=spf1 -all'], $added);
        self::assertCount(2, $s3['added']);
        self::assertSame(['192.0.2.1'], array_column($s3['removed'], 'data'));
        self::assertCount(3, DnsSnapshotRepository::records($s3['snapshot_id']));

        // Snapshots verschiedener Resolver/Hosts sind getrennt
        $s4 = DnsSnapshotRepository::store($id, 'example.com', 'google', $base);
        self::assertTrue($s4['changed']);
        $cmp = DnsSnapshotRepository::diff($s1['snapshot_id'], $s3['snapshot_id']);
        self::assertCount(2, $cmp['added']);
        self::assertCount(1, $cmp['removed']);
    }

    // ---- Findings ------------------------------------------------------------------------------------

    private function draft(string $rule, string $sev, string $subject = ''): array
    {
        return ['rule_id' => $rule, 'title' => "Titel $rule", 'category' => 'Test', 'severity' => $sev, 'reasoning' => 'Begründung', 'recommendation' => 'Empfehlung',
            'subject' => $subject, 'evidence' => ['k' => 'v'], 'source' => 'Testquelle'];
    }

    public function testFindingLifecycleCreateUpdateResolveReopen(): void
    {
        $id = (int) $this->domain()['id'];
        $r = FindingRepository::reconcile($id, 'email', [$this->draft('a', 'high'), $this->draft('b', 'low')]);
        self::assertSame(2, $r['created']);

        $r = FindingRepository::reconcile($id, 'email', [$this->draft('a', 'medium')]);
        self::assertSame(1, $r['updated']);
        self::assertSame(1, $r['resolved'], 'b ist nicht mehr festgestellt → automatisch behoben');
        $rows = FindingRepository::search(['status' => '']);
        $byRule = array_column($rows, null, 'rule_id');
        self::assertSame('medium', $byRule['a']['severity'], 'Schweregrad wird aktualisiert');
        self::assertSame('resolved', $byRule['b']['status']);
        $events = array_column(FindingRepository::events((int) $byRule['a']['id']), 'event');
        self::assertContains('created', $events);
        self::assertContains('severity_changed', $events);
        self::assertContains('auto_resolved', array_column(FindingRepository::events((int) $byRule['b']['id']), 'event'));

        $r = FindingRepository::reconcile($id, 'email', [$this->draft('a', 'medium'), $this->draft('b', 'low')]);
        self::assertSame(1, $r['reopened']);
        self::assertSame('open', array_column(FindingRepository::search(['status' => '']), null, 'rule_id')['b']['status']);
        self::assertSame(0, (int) Database::value('SELECT COUNT(*) FROM findings WHERE rule_id = ? AND domain_id = ?', ['b', $id]) - 1, 'kein Duplikat durch Wiederöffnen');
    }

    public function testIgnoredAndAcknowledgedFindingsAreRespected(): void
    {
        $id = (int) $this->domain()['id'];
        FindingRepository::reconcile($id, 'tls', [$this->draft('x', 'high', 'host:443')]);
        $fid = (int) FindingRepository::search([])[0]['id'];
        self::assertTrue(FindingRepository::setStatus($fid, 'ignored', 'bewusst akzeptiert'));
        FindingRepository::reconcile($id, 'tls', [$this->draft('x', 'high', 'host:443')]);
        self::assertSame('ignored', FindingRepository::find($fid)['status'], 'Ignorierte Findings bleiben ignoriert');
        FindingRepository::reconcile($id, 'tls', []);
        self::assertSame('ignored', FindingRepository::find($fid)['status']);
        self::assertFalse(FindingRepository::setStatus($fid, 'nonsense'));
        self::assertFalse(FindingRepository::setStatus(99999, 'open'));

        // Findings anderer Module/Domains werden nicht angefasst
        $other = (int) $this->domain('other.org')['id'];
        FindingRepository::reconcile($other, 'tls', [$this->draft('y', 'low')]);
        FindingRepository::reconcile($id, 'email', []);
        self::assertSame('open', array_column(FindingRepository::search(['domain_id' => $other]), null, 'rule_id')['y']['status']);
    }

    public function testFingerprintsAreStablePerRuleDomainAndSubject(): void
    {
        self::assertSame(FindingRepository::fingerprint('r', 1, 'A.example'), FindingRepository::fingerprint('r', 1, 'a.example'));
        self::assertNotSame(FindingRepository::fingerprint('r', 1, ''), FindingRepository::fingerprint('r', 2, ''));
        $id = (int) $this->domain()['id'];
        FindingRepository::reconcile($id, 'tls', [$this->draft('t', 'low', 'a:443'), $this->draft('t', 'low', 'b:443')]);
        self::assertCount(2, FindingRepository::search([]), 'dieselbe Regel für zwei Subjekte = zwei Findings');
    }

    // ---- Subdomain-Scans ---------------------------------------------------------------------------------

    private function found(array $hosts, array $errors = []): array
    {
        $h = [];
        foreach ($hosts as $name) {
            $h[$name] = ['sources' => ['crtsh' => true], 'not_after' => '2027-01-01 00:00:00', 'not_before' => null, 'issuers' => []];
        }
        return ['hosts' => $h, 'wildcards' => [], 'sources' => ['crtsh' => ['entries' => 1, 'ms' => 1]], 'errors' => $errors];
    }

    public function testSubdomainScanComparison(): void
    {
        $id = (int) $this->domain()['id'];
        $first = SubdomainRepository::saveScan($id, $this->found(['a.example.com', 'b.example.com']));
        self::assertSame([], $first['new'], 'Der erste Scan markiert nichts als "neu"');
        $second = SubdomainRepository::saveScan($id, $this->found(['a.example.com', 'c.example.com']));
        self::assertSame(['c.example.com'], $second['new']);
        self::assertSame(['b.example.com'], $second['missing']);
        $rows = array_column(SubdomainRepository::forDomain($id), null, 'hostname');
        self::assertSame('missing', $rows['b.example.com']['status']);
        self::assertTrue($rows['c.example.com']['is_new']);
        self::assertFalse($rows['a.example.com']['is_new']);

        $third = SubdomainRepository::saveScan($id, $this->found(['a.example.com', 'b.example.com', 'c.example.com']));
        self::assertSame(['b.example.com'], $third['returned']);
        self::assertSame(3, SubdomainRepository::countAll());
    }

    public function testPartialScanDoesNotMarkEntriesAsMissing(): void
    {
        $id = (int) $this->domain()['id'];
        SubdomainRepository::saveScan($id, $this->found(['a.example.com', 'b.example.com']));
        $partial = SubdomainRepository::saveScan($id, $this->found(['a.example.com'], ['certspotter' => 'Rate-Limit']));
        self::assertSame([], $partial['missing'], 'Bei Quellenfehlern darf nichts als verschwunden gelten');
        self::assertTrue($partial['partial']);
        self::assertSame('present', array_column(SubdomainRepository::forDomain($id), null, 'hostname')['b.example.com']['status']);
    }

    // ---- Assets -------------------------------------------------------------------------------------------

    public function testAssetRelationshipsDistinguishObservedFromConfirmed(): void
    {
        $a = AssetRepository::create(['name' => 'web1', 'type' => 'webserver', 'tags' => 'a, b, a']);
        $b = AssetRepository::create(['name' => 'db1', 'type' => 'invalid-type', 'environment' => 'nonsense']);
        self::assertSame('server', AssetRepository::find($b)['type'], 'Unbekannte Typen fallen auf Standard zurück');
        self::assertSame('production', AssetRepository::find($b)['environment']);
        self::assertSame('a, b', AssetRepository::find($a)['tags'], 'Tags werden dedupliziert');
        self::assertFalse(AssetRepository::link($a, $a, 'depends_on'), 'Selbstverknüpfung verboten');
        self::assertFalse(AssetRepository::link($a, $b, 'unbekannt'));
        self::assertTrue(AssetRepository::link($a, $b, 'depends_on', 'observed', false));
        self::assertFalse(AssetRepository::link($a, $b, 'depends_on'), 'Duplikat');
        $rel = AssetRepository::relationships($a)[0];
        self::assertSame('observed', $rel['origin']);
        self::assertSame(0, (int) $rel['confirmed']);
        AssetRepository::confirm((int) $rel['id']);
        $rel = AssetRepository::relationships($a)[0];
        self::assertSame('manual', $rel['origin']);
        self::assertSame(1, (int) $rel['confirmed']);
        AssetRepository::delete($b);
        self::assertSame([], AssetRepository::relationships(), 'Beziehungen werden mit dem Asset gelöscht');
    }

    // ---- Zugriffsschutz mit Datenbank ---------------------------------------------------------------------

    public function testLoginLockoutAfterRepeatedFailures(): void
    {
        $req = new Request('POST', '/login', [], [], ['REMOTE_ADDR' => '198.51.100.20']);
        $_SESSION = [];
        self::assertFalse(Auth::isLockedOut('198.51.100.20'));
        for ($i = 0; $i < 5; $i++) {
            self::assertFalse(Auth::attempt($req, 'admin', 'falsch'));
        }
        self::assertTrue(Auth::isLockedOut('198.51.100.20'));
        self::assertFalse(Auth::isLockedOut('198.51.100.21'), 'Sperre gilt pro IP');
    }

    // ---- Ergebnis-Historie -------------------------------------------------------------------------------

    public function testModuleResultsKeepHistoryAndReturnPrevious(): void
    {
        $id = (int) $this->domain()['id'];
        $a = ModuleResultRepository::save($id, 'email', '', 'pass', 'ok', ['v' => 1, 'checked_at' => 'x']);
        self::assertNull($a['previous']);
        $b = ModuleResultRepository::save($id, 'email', '', 'warn', 'änderung', ['v' => 2]);
        self::assertSame(1, $b['previous']['data']['v']);
        self::assertSame(2, ModuleResultRepository::latest($id, 'email')['data']['v']);
        self::assertCount(2, ModuleResultRepository::history($id, 'email'));
        ActivityRepository::change($id, 'dns.mx_changed', 'MX geändert', ['x' => 1]);
        self::assertSame('dns.mx_changed', ActivityRepository::changes($id)[0]['type']);
    }
}

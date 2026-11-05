<?php
declare(strict_types=1);

namespace DomainScope\Jobs;

use DomainScope\Findings\FindingsEngine;
use DomainScope\Repositories\{ActivityRepository, CertificateRepository, CtRepository, DnsSnapshotRepository, DomainRepository, FindingRepository, IpRepository,
    ModuleResultRepository, RegistrationRepository, SubdomainRepository};
use DomainScope\Services\DNS\{DnsExplorerService, DnsLookup, DohClient};
use DomainScope\Services\DNSSEC\DnssecService;
use DomainScope\Services\EmailSecurity\{DkimAnalyzer, EmailSecurityService};
use DomainScope\Services\Http\HttpCheckService;
use DomainScope\Services\IPIntelligence\IpIntelligenceService;
use DomainScope\Services\RDAP\RdapClient;
use DomainScope\Services\Subdomains\{SubdomainDiscovery, TakeoverChecker};
use DomainScope\Services\EmailSecurity\HardeningService;
use DomainScope\Services\TLS\TlsInspector;
use DomainScope\Services\WHOIS\WhoisClient;
use DomainScope\Support\{Config, Database, DataSources, Logger, Settings};
use DomainScope\Validation\DomainName;
use DomainScope\Validation\IpClassifier;

/**
 * Führt Prüfmodule für eine Domain aus, speichert Ergebnisse/Snapshots, erkennt Änderungen
 * und gleicht die Findings ab. Gemeinsam genutzt von Web-Oberfläche und Cron.
 */
final class ModuleRunner
{
    public const MODULES = [
        'dns' => 'DNS-Snapshot', 'registration' => 'RDAP/WHOIS', 'email' => 'E-Mail-Sicherheit', 'tls' => 'TLS-Zertifikate',
        'dnssec' => 'DNSSEC & Delegation', 'http' => 'HTTP-Erreichbarkeit', 'ips' => 'IP & ASN', 'subdomains' => 'Subdomains (passiv)', 'hardening' => 'Härtung (CAA/DANE/STARTTLS)',
    ];
    private const APEX_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA'];

    private DohClient $doh;

    public function __construct(?DohClient $doh = null)
    {
        $this->doh = $doh ?? new DohClient();
    }

    /**
     * @param array<string,mixed> $domain Zeile aus domains
     * @param array<string,mixed> $opts
     * @return array{ok:bool,status:string,message:string,data:array<string,mixed>,ms:int}
     */
    public function run(array $domain, string $module, array $opts = []): array
    {
        if (!isset(self::MODULES[$module])) {
            return ['ok' => false, 'status' => 'error', 'message' => 'Unbekanntes Modul.', 'data' => [], 'ms' => 0];
        }
        $started = microtime(true);
        if (PHP_SAPI !== 'cli') {
            @set_time_limit(240); // Prüfläufe (z. B. CT-Abfragen) können länger als das Standardlimit dauern
        }
        try {
            $res = match ($module) {
                'dns' => $this->dns($domain, $opts),
                'registration' => $this->registration($domain, $opts),
                'email' => $this->email($domain, $opts),
                'tls' => $this->tls($domain, $opts),
                'dnssec' => $this->dnssec($domain, $opts),
                'hardening' => $this->hardening($domain, $opts),
                'http' => $this->http($domain, $opts),
                'ips' => $this->ips($domain, $opts),
                'subdomains' => $this->subdomains($domain, $opts),
            };
        } catch (\Throwable $e) {
            Logger::exception($e);
            $res = ['ok' => false, 'status' => 'error', 'message' => 'Interner Fehler: ' . (cfg('app.debug') ? $e->getMessage() : 'siehe Log'), 'data' => []];
        }
        $res['ms'] = (int) round((microtime(true) - $started) * 1000);
        DataSources::flush();
        return $res;
    }

    /**
     * Führt alle Module nacheinander aus und protokolliert einen Scan-Job.
     *
     * @param string[]|null $modules
     * @return array{job_id:int,status:string,results:array<string,array>}
     */
    public function runAll(array $domain, string $trigger = 'manual', ?array $modules = null, array $opts = []): array
    {
        $modules ??= ['dns', 'registration', 'email', 'tls', 'dnssec', 'hardening', 'http', 'ips'];
        $jobId = Database::insert('scan_jobs', [
            'domain_id' => $domain['id'], 'trigger_type' => $trigger, 'status' => 'running', 'started_at' => Database::now(),
        ]);
        $results = [];
        $failed = 0;
        foreach ($modules as $m) {
            $r = $this->run($domain, $m, $opts);
            $results[$m] = $r;
            if (!$r['ok']) {
                $failed++;
            }
            Database::insert('scan_results', [
                'job_id' => $jobId, 'module' => $m, 'status' => $r['ok'] ? 'ok' : 'failed',
                'message' => mb_substr($r['message'], 0, 480), 'duration_ms' => $r['ms'],
            ]);
        }
        $status = $failed === 0 ? 'ok' : ($failed === count($modules) ? 'failed' : 'partial');
        Database::update('scan_jobs', [
            'status' => $status, 'finished_at' => Database::now(),
            'message' => ($failed === 0 ? 'Alle Module erfolgreich' : "$failed von " . count($modules) . ' Modulen fehlgeschlagen'),
        ], 'id = ?', [$jobId]);
        DomainRepository::touch((int) $domain['id']);
        ActivityRepository::log('scan', "Prüfung von {$domain['unicode_name']} abgeschlossen ($status)", (int) $domain['id']);
        return ['job_id' => $jobId, 'status' => $status, 'results' => $results];
    }

    // ------------------------------------------------------------------ DNS

    /** @return array<string,mixed> */
    private function dns(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $resolver = (string) ($opts['resolver'] ?? cfg('app.dns.default_resolver'));
        $explorer = new DnsExplorerService($this->doh);
        $plan = [[$name, self::APEX_TYPES], ['_dmarc.' . $name, ['TXT']], ['www.' . $name, ['A', 'AAAA', 'CNAME']]];
        if (!empty($opts['host']) && $opts['host'] !== $name) {
            $plan[] = [(string) $opts['host'], ['A', 'AAAA', 'CNAME', 'MX', 'TXT']];
        }
        $summary = [];
        $changes = 0;
        $allErrors = 0;
        $ipLinks = [];
        foreach ($plan as [$host, $types]) {
            $lookup = $explorer->lookup($host, $types, [$resolver]);
            $records = [];
            $errors = [];
            foreach ($lookup['results'][$resolver] as $type => $r) {
                if (in_array($r['status'], ['timeout', 'error', 'servfail', 'refused', 'formerr'], true)) {
                    $errors[$type] = $r['status'] . ': ' . ($r['error'] ?? $r['explanation']);
                    continue;
                }
                foreach ($r['answer'] as $rec) {
                    $records[] = ['name' => $rec['name'], 'type' => $rec['type'], 'ttl' => $rec['ttl'], 'data' => $rec['data']];
                    if (in_array($rec['type'], ['A', 'AAAA'], true)) {
                        $ipLinks[] = [$rec['name'], $rec['data'], $rec['type']];
                    }
                }
            }
            $allErrors += count($errors);
            // Bei Teilfehlern keinen neuen Snapshot erzeugen, der fälschlich "Records entfernt" melden würde
            if ($errors !== [] && count($errors) === count($lookup['results'][$resolver])) {
                $summary[$host] = ['error' => 'alle Abfragen fehlgeschlagen'];
                continue;
            }
            if ($errors !== []) {
                $summary[$host] = ['partial' => $errors];
                continue;
            }
            $stored = DnsSnapshotRepository::store($id, $host, $resolver, $records);
            $summary[$host] = ['snapshot_id' => $stored['snapshot_id'], 'changed' => $stored['changed'], 'records' => count($records)];
            if ($stored['changed'] && $stored['previous_id'] !== null) {
                $changes += $this->recordDnsChanges($id, $host, $stored['added'], $stored['removed']);
            }
        }
        foreach ($ipLinks as [$host, $ip, $type]) {
            if (IpClassifier::isValid($ip)) {
                IpRepository::link($id, IpRepository::ensure($ip), $host, $type);
            }
        }
        // Resolver-Konsistenz
        $cons = $explorer->consistency($name);
        $drafts = FindingsEngine::forDnsConsistency($name, $cons['diffs']);
        $okLookups = array_sum(array_map(static fn($t) => count(array_filter($t, static fn($r) => !in_array($r['status'], ['timeout', 'error'], true))), $cons['lookup']['results']));
        if ($okLookups >= 6) {
            FindingRepository::reconcile($id, 'dns', $drafts);
        }
        ModuleResultRepository::save($id, 'dns_consistency', '', $cons['diffs'] === [] ? 'pass' : 'warn',
            $cons['diffs'] === [] ? 'Resolver liefern konsistente Antworten' : 'Abweichungen bei ' . implode(', ', array_keys($cons['diffs'])), ['diffs' => $cons['diffs']]);
        $this->touchDomain($domain);
        return [
            'ok' => $allErrors === 0, 'status' => $allErrors === 0 ? 'ok' : 'partial',
            'message' => $allErrors === 0 ? 'DNS-Snapshot erstellt' . ($changes ? " ($changes Änderung(en))" : '') : "$allErrors Abfrage(n) fehlgeschlagen",
            'data' => ['summary' => $summary, 'changes' => $changes, 'consistency' => $cons['diffs']],
        ];
    }

    /** @return int Anzahl erzeugter Änderungsereignisse */
    private function recordDnsChanges(int $domainId, string $host, array $added, array $removed): int
    {
        $n = 0;
        $groups = [];
        foreach (['added' => $added, 'removed' => $removed] as $kind => $recs) {
            foreach ($recs as $r) {
                $type = $r['type'];
                if ($type === 'TXT' && preg_match('/^v=spf1\b/i', $r['data'])) {
                    $key = 'email.spf_changed';
                } elseif ($type === 'TXT' && str_starts_with($host, '_dmarc.')) {
                    $key = 'email.dmarc_changed';
                } elseif ($type === 'MX') {
                    $key = 'dns.mx_changed';
                } elseif ($type === 'NS') {
                    $key = 'dns.ns_changed';
                } elseif (in_array($type, ['A', 'AAAA'], true)) {
                    $key = 'ip.mapping_changed';
                } else {
                    $key = 'dns.record_' . $kind;
                }
                $groups[$key][$kind][] = $r;
            }
        }
        $label = [
            'email.spf_changed' => 'SPF-Record geändert', 'email.dmarc_changed' => 'DMARC-Record geändert', 'dns.mx_changed' => 'MX-Records geändert',
            'dns.ns_changed' => 'NS-Records geändert', 'ip.mapping_changed' => 'IP-Zuordnung geändert', 'dns.record_added' => 'DNS-Record hinzugefügt',
            'dns.record_removed' => 'DNS-Record entfernt',
        ];
        foreach ($groups as $key => $g) {
            $fmt = static fn(array $recs) => implode('; ', array_map(static fn($r) => $r['name'] . ' ' . $r['type'] . ' ' . mb_strimwidth($r['data'], 0, 80, '…'), array_slice($recs, 0, 4)));
            $parts = [];
            if (!empty($g['added'])) {
                $parts[] = '+ ' . $fmt($g['added']);
            }
            if (!empty($g['removed'])) {
                $parts[] = '− ' . $fmt($g['removed']);
            }
            ActivityRepository::change($domainId, $key, ($label[$key] ?? $key) . ' (' . $host . '): ' . implode(' | ', $parts), $g);
            $n++;
        }
        return $n;
    }

    // --------------------------------------------------------- Registrierung

    /** @return array<string,mixed> */
    private function registration(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $reg = (new RdapClient())->domain($name);
        if (!$reg['ok'] && Settings::bool('whois_fallback') && in_array($reg['error_code'] ?? '', ['unsupported_tld', 'unreachable', 'timeout', 'http_error', 'invalid_response'], true)) {
            $whois = (new WhoisClient())->domain($name);
            if ($whois['ok']) {
                $whois['notes'][] = 'RDAP nicht verfügbar (' . $reg['error'] . ') – WHOIS-Fallback verwendet.';
                $reg = $whois;
            } else {
                $reg['error'] .= ' WHOIS-Fallback: ' . $whois['error'];
            }
        }
        if (!$reg['ok']) {
            $level = in_array($reg['error_code'] ?? '', ['not_found', 'unsupported_tld'], true) ? 'partial' : 'error';
            return ['ok' => false, 'status' => $level, 'message' => (string) $reg['error'], 'data' => $reg];
        }
        $saved = RegistrationRepository::save($id, $reg);
        if ($saved['changed'] && $saved['previous'] !== null) {
            $this->registrationChanges($id, $saved['previous'], $reg);
        }
        FindingRepository::reconcile($id, 'registration', FindingsEngine::forRegistration($name, $reg));
        $this->touchDomain($domain);
        return ['ok' => true, 'status' => 'ok', 'message' => strtoupper($reg['source']) . ': ' . ($reg['registrar'] ?? 'Registrar unbekannt'), 'data' => $reg];
    }

    private function registrationChanges(int $id, array $prev, array $new): void
    {
        $emit = static function (string $type, string $msg) use ($id): void {
            ActivityRepository::change($id, $type, $msg);
        };
        if (($prev['registrar'] ?? null) !== ($new['registrar'] ?? null)) {
            $emit('registration.registrar_changed', 'Registrar geändert: ' . ($prev['registrar'] ?? '–') . ' → ' . ($new['registrar'] ?? '–'));
        }
        if (($prev['expires_at'] ?? null) !== ($new['expires_at'] ?? null)) {
            $emit('registration.expiry_changed', 'Ablaufdatum geändert: ' . ($prev['expires_at'] ?? '–') . ' → ' . ($new['expires_at'] ?? '–'));
        }
        $ps = $prev['statuses'] ?? [];
        $ns = $new['statuses'] ?? [];
        sort($ps);
        sort($ns);
        if ($ps !== $ns) {
            $emit('registration.status_changed', 'Domainstatus geändert: ' . (implode(', ', $ps) ?: '–') . ' → ' . (implode(', ', $ns) ?: '–'));
        }
        $pn = $prev['nameservers'] ?? [];
        $nn = $new['nameservers'] ?? [];
        if ($pn !== $nn) {
            $emit('registration.ns_changed', 'Nameserver laut Registry geändert: ' . (implode(', ', $pn) ?: '–') . ' → ' . (implode(', ', $nn) ?: '–'));
        }
    }

    // ----------------------------------------------------------------- E-Mail

    /** @return array<string,mixed> */
    private function email(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $selectors = array_merge(
            explode(',', (string) $domain['dkim_selectors']),
            explode(',', Settings::get('dkim_selectors')),
            isset($opts['selectors']) ? (array) $opts['selectors'] : []
        );
        $autoscan = isset($opts['dkim_autoscan']) ? (bool) $opts['dkim_autoscan'] : Settings::bool('dkim_autoscan');
        $svc = new EmailSecurityService(new DnsLookup($this->doh, null, 140));
        $report = $svc->run($name, $selectors, $autoscan);
        $failedChecks = count(array_filter($report['checks'], static fn($c) => $c['status'] === 'error'));
        $worst = $report['tally']['fail'] > 0 ? 'fail' : ($report['tally']['warn'] > 0 ? 'warn' : 'pass');
        $summary = sprintf('%d ok, %d Warnung, %d Fehler, %d nicht konfiguriert', $report['tally']['pass'], $report['tally']['warn'], $report['tally']['fail'], $report['tally']['none']);
        $saved = ModuleResultRepository::save($id, 'email', '', $worst, $summary, $report, $report['duration_ms']);
        $prev = $saved['previous']['data']['checks'] ?? null;
        if ($prev !== null) {
            foreach (['spf' => 'email.spf_changed', 'dmarc' => 'email.dmarc_changed'] as $c => $type) {
                if (($prev[$c]['record'] ?? null) !== ($report['checks'][$c]['record'] ?? null)
                    && !($this->recentChange($id, $type))) {
                    ActivityRepository::change($id, $type, strtoupper($c) . '-Record geändert: ' . mb_strimwidth((string) ($prev[$c]['record'] ?? '–'), 0, 100, '…') . ' → ' . mb_strimwidth((string) ($report['checks'][$c]['record'] ?? '–'), 0, 100, '…'));
                }
            }
        }
        if ($failedChecks < 3) {
            FindingRepository::reconcile($id, 'email', FindingsEngine::forEmail($name, $report));
        }
        $this->touchDomain($domain);
        return ['ok' => $failedChecks === 0, 'status' => $failedChecks ? 'partial' : 'ok', 'message' => $summary, 'data' => $report];
    }

    private function recentChange(int $domainId, string $type): bool
    {
        return (bool) Database::value('SELECT COUNT(*) FROM change_events WHERE domain_id = ? AND type = ? AND detected_at > ?', [$domainId, $type, gmdate('Y-m-d H:i:s', time() - 120)]);
    }

    // -------------------------------------------------------------------- TLS

    /** @return array<string,mixed> */
    private function tls(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $hosts = [];
        if (!empty($opts['host'])) {
            $hosts[] = [(string) $opts['host'], (int) ($opts['port'] ?? 443), true];
        } else {
            $ports = array_filter(array_map('intval', explode(',', Settings::get('tls_ports'))));
            foreach ($ports ?: [443] as $p) {
                $hosts[] = [$name, $p, true];
                $hosts[] = ['www.' . $name, $p, false];
            }
        }
        $inspector = new TlsInspector();
        $results = [];
        $bad = 0;
        foreach ($hosts as [$host, $port, $required]) {
            $r = $inspector->inspect($host, $port);
            if (!$required && $r['status'] === 'unreachable' && in_array($r['error_stage'] ?? '', ['dns', 'blocked', 'connect'], true)) {
                continue; // optionale www-Variante existiert nicht
            }
            $saved = CertificateRepository::save($id, $r);
            if ($saved['new_certificate'] && $saved['previous_fingerprint'] !== null) {
                ActivityRepository::change($id, 'tls.new_certificate', "Neues Zertifikat für {$host}:{$port} (Aussteller " . ($r['certificate']['issuer_cn'] ?? '?') . ')');
            } elseif ($saved['previous_fingerprint'] === null && $r['certificate']) {
                ActivityRepository::log('tls', "Zertifikat von {$host}:{$port} erstmals erfasst", $id);
            }
            $results[$host . ':' . $port] = $r;
            if ($r['status'] !== 'ok') {
                $bad++;
            }
        }
        // Findings über alle zuletzt bekannten Prüfungen der Domain abgleichen (nicht nur die aktuelle)
        $latest = [];
        foreach (CertificateRepository::latestForDomain($id) as $row) {
            $d = $row['details'];
            if ($d) {
                $latest[] = $d;
            }
        }
        FindingRepository::reconcile($id, 'tls', FindingsEngine::forTls($name, $latest));
        $this->touchDomain($domain);
        $ok = $results !== [];
        return [
            'ok' => $ok, 'status' => $ok ? ($bad ? 'partial' : 'ok') : 'error',
            'message' => $ok ? count($results) . ' Endpunkt(e) geprüft' . ($bad ? ", $bad mit Befund" : '') : 'Kein TLS-Endpunkt erreichbar',
            'data' => ['results' => $results],
        ];
    }

    // ----------------------------------------------------------------- DNSSEC

    /** @return array<string,mixed> */
    private function dnssec(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $a = (new DnssecService($this->doh))->analyze($name);
        $unusable = array_sum(array_map(static fn($r) => $r['usable'] ? 0 : 1, $a['resolvers']));
        $status = match (true) {
            in_array($a['state'], ['broken'], true) => 'fail',
            in_array($a['state'], ['dnskey_only'], true) => 'warn',
            $a['state'] === 'unsigned' => 'none',
            default => 'pass',
        };
        $saved = ModuleResultRepository::save($id, 'dnssec', '', $status, 'DNSSEC-Zustand: ' . $a['state'], $a, $a['duration_ms']);
        $prev = $saved['previous']['data'] ?? null;
        if ($prev !== null && ($prev['state'] ?? null) !== $a['state']) {
            ActivityRepository::change($id, 'dnssec.state_changed', 'DNSSEC-Zustand geändert: ' . ($prev['state'] ?? '–') . ' → ' . $a['state']);
        }
        if ($unusable < 2) {
            FindingRepository::reconcile($id, 'dnssec', FindingsEngine::forDnssec($name, $a));
        }
        $this->touchDomain($domain);
        return ['ok' => $unusable < 2, 'status' => $unusable ? 'partial' : 'ok', 'message' => 'DNSSEC: ' . $a['state'], 'data' => $a];
    }

    // ------------------------------------------------------------------- HTTP

    /** @return array<string,mixed> */
    private function http(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $svc = new HttpCheckService();
        $hosts = !empty($opts['host']) ? [(string) $opts['host']] : [$name, 'www.' . $name];
        $out = [];
        foreach ($hosts as $h) {
            $r = $svc->check($h);
            if ($h !== $name && !$r['https']['reachable'] && !$r['http']['reachable'] && in_array($r['https']['error_code'], ['blocked', 'connect'], true)) {
                continue;
            }
            $st = $r['https']['reachable'] ? 'pass' : ($r['http']['reachable'] ? 'warn' : 'unknown');
            ModuleResultRepository::save($id, 'http', $h, $st, $r['https']['reachable'] ? 'HTTPS ' . $r['https']['status'] : 'HTTPS nicht erreichbar', $r);
            $out[$h] = $r;
        }
        $drafts = [];
        foreach (Database::all("SELECT m.data FROM module_results m JOIN (SELECT subject, MAX(id) mid FROM module_results WHERE domain_id = ? AND module = 'http' GROUP BY subject) x ON x.mid = m.id", [$id]) as $row) {
            $drafts = array_merge($drafts, FindingsEngine::forHttp($name, json_decode($row['data'], true) ?: []));
        }
        FindingRepository::reconcile($id, 'http', $drafts);
        $this->touchDomain($domain);
        $ok = $out !== [];
        return ['ok' => $ok, 'status' => $ok ? 'ok' : 'error', 'message' => $ok ? count($out) . ' Host(s) geprüft' : 'Keine Antwort', 'data' => ['results' => $out]];
    }

    // -------------------------------------------------------------------- IPs

    /** @return array<string,mixed> */
    private function ips(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $linked = IpRepository::forDomain($id);
        $svc = new IpIntelligenceService($this->doh);
        $limit = (int) ($opts['limit'] ?? 15);
        $done = 0;
        $seen = [];
        foreach ($linked as $row) {
            if (isset($seen[$row['address']])) {
                continue;
            }
            $seen[$row['address']] = true;
            $fresh = $row['checked_at'] !== null && strtotime($row['checked_at'] . ' UTC') > time() - 7 * 86400;
            if ($fresh && empty($opts['force'])) {
                continue;
            }
            if ($done >= $limit) {
                break;
            }
            if (!IpClassifier::isPublic($row['address'])) {
                continue;
            }
            IpRepository::saveLookup($svc->lookup($row['address']));
            $done++;
        }
        DataSources::flush();
        return ['ok' => true, 'status' => 'ok', 'message' => $done . ' IP-Adresse(n) angereichert (' . count($seen) . ' bekannt)', 'data' => ['enriched' => $done, 'known' => count($seen)]];
    }

    // ------------------------------------------------------------- Subdomains

    /** @return array<string,mixed> */
    private function subdomains(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $disc = new SubdomainDiscovery();
        $found = $disc->discover($name);
        if ($found['sources'] === []) {
            return ['ok' => false, 'status' => 'error', 'message' => 'Keine Datenquelle erreichbar: ' . implode(' | ', array_map(fn($k, $v) => "$k: $v", array_keys($found['errors']), $found['errors'])), 'data' => $found];
        }
        $saved = SubdomainRepository::saveScan($id, $found);
        if ($saved['new']) {
            ActivityRepository::change($id, 'subdomain.new', count($saved['new']) . ' neue Subdomain(s): ' . implode(', ', array_slice($saved['new'], 0, 6)) . (count($saved['new']) > 6 ? ' …' : ''), ['hosts' => $saved['new']]);
        }
        if ($saved['missing']) {
            ActivityRepository::log('subdomain', count($saved['missing']) . ' Subdomain(s) nicht mehr in CT-Daten gefunden', $id);
        }
        $resolved = [];
        if (($opts['resolve'] ?? Settings::bool('subdomain_resolve')) && $found['hosts']) {
            $limit = (int) ($opts['limit'] ?? Settings::int('subdomain_resolve_limit'));
            $resolved = $disc->resolve($this->doh, array_keys($found['hosts']), $limit, (string) cfg('app.dns.default_resolver'));
            SubdomainRepository::saveResolution($id, $resolved);
            foreach ($resolved as $host => $r) {
                foreach ($r['ips'] as $ip) {
                    if (IpClassifier::isValid($ip)) {
                        IpRepository::link($id, IpRepository::ensure($ip), $host, str_contains($ip, ':') ? 'AAAA' : 'A', 'subdomain');
                    }
                }
            }
        }
        $all = [];
        foreach (SubdomainRepository::forDomain($id) as $row) {
            if ($row['status'] === 'present' && $row['resolved_status']) {
                $all[$row['hostname']] = ['status' => $row['resolved_status'], 'ips' => $row['resolved_ips'], 'cname' => $row['resolved_cname']];
            }
        }
        // Takeover-Indizien (nur für CNAME-Hosts, begrenzt)
        $prev = ModuleResultRepository::latest($id, 'takeover');
        $takeover = $prev['data']['hosts'] ?? [];
        $checker = new TakeoverChecker($this->doh);
        $n = 0;
        foreach (SubdomainRepository::forDomain($id) as $row) {
            if ($row['status'] !== 'present' || empty($row['resolved_cname'])) {
                continue;
            }
            if ($n >= 25) {
                break;
            }
            $n++;
            $takeover[$row['hostname']] = $checker->check($row['hostname'], (string) $row['resolved_cname']);
        }
        $present = array_column(array_filter(SubdomainRepository::forDomain($id), static fn($r) => $r['status'] === 'present'), 'hostname');
        $takeover = array_intersect_key($takeover, array_flip($present));
        if ($takeover !== []) {
            $bad = count(array_filter($takeover, static fn($t) => $t['status'] === 'vulnerable'));
            ModuleResultRepository::save($id, 'takeover', '', $bad ? 'fail' : 'pass', $bad ? "$bad mögliche(r) Takeover" : 'keine Hinweise', ['hosts' => $takeover]);
        }
        FindingRepository::reconcile($id, 'subdomains', FindingsEngine::forSubdomains($name, $all, $takeover));
        // Certificate Transparency: neue Zertifikate seit dem Ausgangsbestand
        $ctNew = 0;
        if (($found['certs'] ?? null) !== null) {
            $ct = CtRepository::saveScan($id, $found['certs']);
            $ctNew = count($ct['new']);
            if ($ctNew > 0) {
                $unknown = count(array_filter($ct['new'], static fn($c) => !$c['known_issuer']));
                ActivityRepository::change($id, 'tls.ct_new_certificate', "$ctNew neue(s) Zertifikat(e) in CT-Logs" . ($unknown ? " ($unknown von unbekannter CA)" : ''), ['serials' => array_column($ct['new'], 'serial')]);
            }
            FindingRepository::reconcile($id, 'ct', FindingsEngine::forCt($name, CtRepository::recentNew($id, 30)));
        }
        $this->touchDomain($domain);
        $msg = $saved['total'] . ' Subdomain(s) (' . count($saved['new']) . ' neu, ' . count($saved['missing']) . ' nicht mehr gefunden)';
        if ($found['errors']) {
            $msg .= ' – Teilfehler: ' . implode(', ', array_keys($found['errors']));
        }
        return ['ok' => true, 'status' => $found['errors'] ? 'partial' : 'ok', 'message' => $msg, 'data' => ['scan' => $saved, 'errors' => $found['errors'], 'resolved' => count($resolved)]];
    }

    // --------------------------------------------------------------- Härtung

    /** @return array<string,mixed> */
    private function hardening(array $domain, array $opts): array
    {
        $id = (int) $domain['id'];
        $name = (string) $domain['name'];
        $mxHosts = [];
        $mail = ModuleResultRepository::latest($id, 'email');
        foreach (($mail['data']['checks']['mx']['hosts'] ?? []) as $h) {
            $mxHosts[] = $h['host'];
        }
        if ($mxHosts === [] && $mail === null) {
            foreach ((new DnsLookup($this->doh))->values($name, 'MX')['values'] as $v) {
                if (($p = \DomainScope\Services\DNS\RecordFormatter::parseMx($v)) && $p['host'] !== '') {
                    $mxHosts[] = $p['host'];
                }
            }
        }
        $issuers = [];
        foreach (CertificateRepository::latestForDomain($id) as $c) {
            if (!empty($c['issuer'])) {
                $issuers[] = (string) $c['issuer'];
            }
        }
        $dn = ModuleResultRepository::latest($id, 'dnssec');
        $starttls = isset($opts['starttls']) ? (bool) $opts['starttls'] : Settings::bool('starttls_check');
        $r = (new HardeningService(new DnsLookup($this->doh)))->run($name, $mxHosts, $issuers, $dn['data']['state'] ?? null, $starttls);
        $drafts = FindingsEngine::forHardening($name, $r);
        $bad = array_filter($drafts, static fn($d) => in_array($d['severity'], ['critical', 'high', 'medium'], true));
        $status = $bad ? 'warn' : 'pass';
        $prev = ModuleResultRepository::latest($id, 'hardening');
        if ($prev && !$starttls && ($prev['data']['starttls'] ?? null) !== null) {
            $r['starttls'] = $prev['data']['starttls']; // letztes explizites STARTTLS-Ergebnis behalten
            $r['starttls_requested'] = false;
            $drafts = FindingsEngine::forHardening($name, $r);
        }
        ModuleResultRepository::save($id, 'hardening', '', $status, count($drafts) . ' Hinweis(e)', $r);
        FindingRepository::reconcile($id, 'hardening', $drafts);
        $this->touchDomain($domain);
        return ['ok' => true, 'status' => 'ok', 'message' => 'CAA/DANE' . ($starttls ? '/STARTTLS' : '') . ': ' . count($drafts) . ' Hinweis(e)', 'data' => $r];
    }

    private function touchDomain(array $domain): void
    {
        DomainRepository::touch((int) $domain['id']);
    }
}

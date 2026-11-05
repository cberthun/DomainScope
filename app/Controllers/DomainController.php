<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Jobs\ModuleRunner;
use DomainScope\Repositories\{ActivityRepository, CertificateRepository, DnsSnapshotRepository, DomainRepository, FindingRepository, IpRepository,
    ModuleResultRepository, RegistrationRepository, SubdomainRepository};
use DomainScope\Support\{Database, Request, Response, Settings, View};
use DomainScope\Validation\{DomainName, Target};

final class DomainController extends Controller
{
    public const TABS = [
        'overview' => ['Übersicht', 'dashboard'], 'dns' => ['DNS', 'network'], 'registration' => ['RDAP/WHOIS', 'file-text'],
        'email' => ['E-Mail', 'mail'], 'tls' => ['TLS', 'lock'], 'dnssec' => ['DNSSEC', 'shield-check'],
        'subdomains' => ['Subdomains', 'git-branch'], 'hardening' => ['Härtung', 'lock'], 'ips' => ['IP & ASN', 'server'], 'http' => ['HTTP', 'globe'],
        'history' => ['Verlauf', 'history'], 'findings' => ['Findings', 'alert-triangle'], 'notes' => ['Notizen', 'edit'],
    ];

    public function index(Request $r): Response
    {
        return $this->page('domains', [
            'title' => 'Domain Explorer', 'section' => 'domains', 'scripts' => ['domain-explorer.js'],
            'breadcrumbs' => [['Domain Explorer']], 'domains' => DomainRepository::all(),
            'staleHours' => Settings::int('stale_hours') ?: 48, 'error' => $r->str('error'),
        ]);
    }

    /** Normalisiert die Eingabe und leitet zur passenden Ansicht weiter (Domain, Subdomain, URL, IP). */
    public function lookup(Request $r): Response
    {
        $t = Target::parse($r->str('target'));
        if (!$t->valid()) {
            $this->flash('error', $t->error ?? 'Ungültige Eingabe.');
            return $this->redirect('/domains');
        }
        if ($t->isIp()) {
            return $this->redirect('/ip/' . rawurlencode((string) $t->host));
        }
        if ($t->registrable === null) {
            $this->flash('error', $t->error ?? 'Keine registrierbare Domain.');
            return $this->redirect('/domains');
        }
        $domain = DomainRepository::ensure($t);
        $query = $t->isSubdomain ? ['host' => $t->host] : [];
        if ($r->str('autorun') === '1' && $domain['last_checked_at'] === null) {
            (new ModuleRunner())->runAll($domain, 'manual');
        }
        return $this->redirect(url('/domain/' . rawurlencode($domain['name']), $query));
    }

    public function show(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            // Eingabe könnte eine neue Domain sein → normalisieren und anlegen
            $t = Target::parse((string) $r->params['domain']);
            if ($t->isDomain() && $t->registrable !== null) {
                $domain = DomainRepository::ensure($t);
            } else {
                return $this->notFound('Domain');
            }
        }
        $tab = isset(self::TABS[$r->str('tab')]) ? $r->str('tab') : 'overview';
        $host = $this->host($domain, $r);
        $panel = View::partial('partials/domain/' . $tab, $this->tabData($tab, $domain, $host));
        $counts = Database::one("SELECT SUM(severity IN ('critical','high')) AS serious, COUNT(*) AS total FROM findings WHERE domain_id = ? AND status IN ('open','acknowledged')", [$domain['id']]);

        return $this->page('domain', [
            'title' => $domain['unicode_name'], 'section' => 'domains', 'scripts' => ['domain-explorer.js'],
            'breadcrumbs' => [['Domain Explorer', '/domains'], [$domain['unicode_name']]],
            'domain' => $domain, 'host' => $host, 'tab' => $tab, 'tabs' => self::TABS, 'panel' => $panel, 'counts' => $counts,
            'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    public function tab(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        $tab = (string) $r->params['tab'];
        if ($domain === null || !isset(self::TABS[$tab])) {
            return $this->notFound();
        }
        return $this->partial('partials/domain/' . $tab, $this->tabData($tab, $domain, $this->host($domain, $r)));
    }

    public function run(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        $module = (string) $r->params['module'];
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $opts = [];
        $host = $r->str('host');
        if ($host !== '') {
            $ascii = DomainName::normalize($host);
            if ($ascii !== null && ($ascii === $domain['name'] || str_ends_with($ascii, '.' . $domain['name']))) {
                $opts['host'] = $ascii;
            }
        }
        if ($module === 'email') {
            $sel = $this->listInput('selectors');
            if ($sel) {
                DomainRepository::setSelectors((int) $domain['id'], implode(',', array_slice($sel, 0, 20)));
                $domain['dkim_selectors'] = implode(',', array_slice($sel, 0, 20));
            }
            $opts['dkim_autoscan'] = $r->str('autoscan') === '1';
        }
        if ($module === 'tls' && $r->int('port')) {
            $opts['port'] = $r->int('port');
        }
        if ($module === 'hardening') {
            $opts['starttls'] = $r->str('starttls') === '1';
        }
        if ($module === 'subdomains') {
            $opts['resolve'] = $r->str('resolve') !== '0';
        }
        $res = (new ModuleRunner())->run($domain, $module, $opts);
        $res['data'] = [];
        if ($r->isAjax()) {
            return $this->json($res);
        }
        $this->flash($res['ok'] ? 'success' : 'error', ModuleRunner::MODULES[$module] . ': ' . $res['message']);
        return $this->redirect(url('/domain/' . rawurlencode($domain['name']), ['tab' => $this->tabFor($module)]));
    }

    public function runAll(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $modules = ['dns', 'registration', 'email', 'tls', 'dnssec', 'http', 'ips'];
        if ($r->str('subdomains') === '1') {
            $modules[] = 'subdomains';
        }
        $res = (new ModuleRunner())->runAll($domain, 'manual', $modules);
        if ($r->isAjax()) {
            return $this->json(['ok' => $res['status'] !== 'failed', 'status' => $res['status'], 'message' => 'Prüfung abgeschlossen (' . $res['status'] . ')']);
        }
        $this->flash($res['status'] === 'ok' ? 'success' : 'warn', 'Prüfung abgeschlossen: ' . ui_status_label($res['status']));
        return $this->redirect('/domain/' . rawurlencode($domain['name']));
    }

    public function monitor(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $on = $r->str('monitored') === '1';
        DomainRepository::setMonitored((int) $domain['id'], $on);
        ActivityRepository::log('domain', $domain['unicode_name'] . ($on ? ': regelmäßige Prüfung aktiviert' : ': regelmäßige Prüfung deaktiviert'), (int) $domain['id']);
        $this->flash('success', $on ? 'Domain wird bei Cron-Läufen geprüft.' : 'Domain wird nicht mehr automatisch geprüft.');
        return $this->redirect('/domain/' . rawurlencode($domain['name']));
    }

    public function notes(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        DomainRepository::setNotes((int) $domain['id'], (string) ($r->post['notes'] ?? ''));
        $sel = (new \DomainScope\Services\EmailSecurity\DkimAnalyzer(new \DomainScope\Services\DNS\DnsLookup(new \DomainScope\Services\DNS\DohClient())))->cleanSelectors(explode(',', (string) ($r->post['selectors'] ?? '')));
        DomainRepository::setSelectors((int) $domain['id'], implode(',', $sel));
        $this->flash('success', 'Notizen und DKIM-Selektoren gespeichert.');
        return $this->redirect(url('/domain/' . rawurlencode($domain['name']), ['tab' => 'notes']));
    }

    public function delete(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        if ($r->str('confirm') !== $domain['name']) {
            $this->flash('error', 'Zur Bestätigung muss der Domainname exakt eingegeben werden.');
            return $this->redirect(url('/domain/' . rawurlencode($domain['name']), ['tab' => 'notes']));
        }
        DomainRepository::delete((int) $domain['id']);
        ActivityRepository::log('domain', 'Domain ' . $domain['unicode_name'] . ' gelöscht');
        $this->flash('success', 'Domain und alle zugehörigen Daten gelöscht.');
        return $this->redirect('/domains');
    }

    private function tabFor(string $module): string
    {
        return match ($module) {
            'dns' => 'dns', 'registration' => 'registration', 'email' => 'email', 'tls' => 'tls', 'dnssec' => 'dnssec',
            'http' => 'http', 'ips' => 'ips', 'subdomains' => 'subdomains', 'hardening' => 'hardening', default => 'overview',
        };
    }

    /** Auswahl des Hosts (Subdomain) innerhalb der Domain; Standard: Apex. */
    private function host(array $domain, Request $r): string
    {
        $h = DomainName::normalize($r->str('host'));
        if ($h !== null && ($h === $domain['name'] || str_ends_with($h, '.' . $domain['name']))) {
            return $h;
        }
        return (string) $domain['name'];
    }

    /** @return array<string,mixed> */
    private function tabData(string $tab, array $domain, string $host): array
    {
        $id = (int) $domain['id'];
        $base = ['domain' => $domain, 'host' => $host, 'staleHours' => Settings::int('stale_hours') ?: 48];
        switch ($tab) {
            case 'overview':
                $email = ModuleResultRepository::latest($id, 'email');
                $dnssec = ModuleResultRepository::latest($id, 'dnssec');
                return $base + [
                    'registration' => RegistrationRepository::latest($id), 'email' => $email, 'dnssec' => $dnssec,
                    'tlsChecks' => CertificateRepository::latestForDomain($id),
                    'http' => ModuleResultRepository::latest($id, 'http', $domain['name']),
                    'dnsSnap' => DnsSnapshotRepository::latest($id, $domain['name'], (string) cfg('app.dns.default_resolver')),
                    'ips' => IpRepository::forDomain($id),
                    'findings' => array_slice(FindingRepository::search(['status' => 'active', 'domain_id' => $id]), 0, 6),
                    'subCount' => (int) Database::value("SELECT COUNT(*) FROM subdomains WHERE domain_id = ? AND status = 'present'", [$id]),
                    'consistency' => ModuleResultRepository::latest($id, 'dns_consistency'),
                ];
            case 'dns':
                $resolver = (string) cfg('app.dns.default_resolver');
                $hosts = [$domain['name'], '_dmarc.' . $domain['name'], 'www.' . $domain['name']];
                if ($host !== $domain['name']) {
                    array_unshift($hosts, $host);
                }
                $snaps = [];
                foreach (array_unique($hosts) as $h) {
                    $s = DnsSnapshotRepository::latest($id, $h, $resolver);
                    if ($s) {
                        $snaps[$h] = ['snapshot' => $s, 'records' => DnsSnapshotRepository::records((int) $s['id'])];
                    }
                }
                return $base + ['snaps' => $snaps, 'history' => DnsSnapshotRepository::list($id, null, 15), 'consistency' => ModuleResultRepository::latest($id, 'dns_consistency')];
            case 'registration':
                return $base + ['registration' => RegistrationRepository::latest($id), 'history' => RegistrationRepository::history($id, 10)];
            case 'email':
                return $base + ['email' => ModuleResultRepository::latest($id, 'email'), 'history' => ModuleResultRepository::history($id, 'email', '', 8)];
            case 'tls':
                return $base + ['checks' => CertificateRepository::latestForDomain($id)];
            case 'dnssec':
                return $base + ['dnssec' => ModuleResultRepository::latest($id, 'dnssec')];
            case 'subdomains':
                return $base + ['subdomains' => SubdomainRepository::forDomain($id), 'scans' => SubdomainRepository::scans($id, 8), 'ct' => \DomainScope\Repositories\CtRepository::forDomain($id, 60), 'takeover' => ModuleResultRepository::latest($id, 'takeover')];
            case 'hardening':
                return $base + ['hardening' => ModuleResultRepository::latest($id, 'hardening')];
            case 'ips':
                return $base + ['ips' => IpRepository::forDomain($id)];
            case 'http':
                $rows = Database::all("SELECT m.* FROM module_results m JOIN (SELECT subject, MAX(id) mid FROM module_results WHERE domain_id = ? AND module = 'http' GROUP BY subject) x ON x.mid = m.id ORDER BY m.subject", [$id]);
                foreach ($rows as &$row) {
                    $row['data'] = json_decode((string) $row['data'], true) ?: [];
                }
                return $base + ['results' => $rows];
            case 'history':
                return $base + [
                    'changes' => ActivityRepository::changes($id, 60),
                    'jobs' => Database::all('SELECT * FROM scan_jobs WHERE domain_id = ? ORDER BY id DESC LIMIT 15', [$id]),
                    'dnsHistory' => DnsSnapshotRepository::list($id, null, 12),
                ];
            case 'findings':
                return $base + ['findings' => FindingRepository::search(['domain_id' => $id, 'status' => $_GET['status'] ?? ''])];
            case 'notes':
                return $base;
        }
        return $base;
    }
}

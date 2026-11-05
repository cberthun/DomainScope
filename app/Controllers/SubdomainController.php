<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{DomainRepository, SubdomainRepository};
use DomainScope\Services\DNS\DnsExplorerService;
use DomainScope\Support\{Database, Request, Response, Settings};

final class SubdomainController extends SectionController
{
    protected function section(): string
    {
        return 'subdomains';
    }

    protected function sectionTitle(): string
    {
        return 'Subdomain Intelligence';
    }

    protected function basePath(): string
    {
        return '/subdomains';
    }

    public function index(Request $r): Response
    {
        if (($redirect = $this->redirectIfDomainInput($r)) !== null) {
            return $redirect;
        }
        $stats = [];
        foreach (Database::all("SELECT domain_id, SUM(status='present') AS present, SUM(status='missing') AS missing, MAX(last_seen) AS last_seen FROM subdomains GROUP BY domain_id") as $row) {
            $stats[(int) $row['domain_id']] = $row;
        }
        $scan = [];
        foreach (Database::all('SELECT s.* FROM subdomain_scans s JOIN (SELECT domain_id, MAX(id) mid FROM subdomain_scans GROUP BY domain_id) x ON x.mid = s.id') as $row) {
            $scan[(int) $row['domain_id']] = $row;
        }
        return $this->page('subdomains', [
            'title' => 'Subdomain Intelligence', 'section' => 'subdomains', 'breadcrumbs' => [['Subdomain Intelligence']],
            'domains' => DomainRepository::all(), 'stats' => $stats, 'scan' => $scan, 'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    public function show(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $id = (int) $domain['id'];
        $body = $this->render('partials/subdomain_table', ['domain' => $domain, 'subdomains' => SubdomainRepository::forDomain($id), 'scans' => SubdomainRepository::scans($id, 10), 'ct' => \DomainScope\Repositories\CtRepository::forDomain($id, 60), 'takeover' => \DomainScope\Repositories\ModuleResultRepository::latest($id, 'takeover')]);
        return $this->domainPage($domain, $body, ['scripts' => ['domain-explorer.js']]);
    }

    public function scan(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        return $this->runAndRedirect($domain, 'subdomains', ['resolve' => $r->str('resolve') === '1']);
    }

    public function export(Request $r): Response
    {
        $domain = $this->domainFromRoute();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $rows = [];
        foreach (SubdomainRepository::forDomain((int) $domain['id']) as $s) {
            $rows[] = [
                'hostname' => $s['hostname'], 'status' => $s['status'] === 'present' ? ($s['is_new'] ? 'neu' : 'gefunden') : 'nicht_mehr_gefunden',
                'resolved_status' => (string) $s['resolved_status'], 'ips' => implode(' ', $s['resolved_ips']), 'cname' => (string) $s['resolved_cname'],
                'sources' => implode(' ', $s['sources']), 'cert_not_after' => (string) $s['cert_not_after'],
                'first_seen' => $s['first_seen'], 'last_seen' => $s['last_seen'],
            ];
        }
        $name = 'subdomains_' . $domain['name'];
        if ($r->str('format') === 'json') {
            return Response::download(json_out(['domain' => $domain['name'], 'exported_at' => gmdate('c'), 'note' => 'Passive Funde aus Certificate-Transparency-Logs; kein Nachweis aktueller Erreichbarkeit.', 'subdomains' => $rows], JSON_PRETTY_PRINT), $name . '.json', 'application/json; charset=utf-8');
        }
        $cols = ['hostname', 'status', 'resolved_status', 'ips', 'cname', 'sources', 'cert_not_after', 'first_seen', 'last_seen'];
        return Response::download(DnsExplorerService::toCsv($rows, $cols), $name . '.csv', 'text/csv; charset=utf-8');
    }
}

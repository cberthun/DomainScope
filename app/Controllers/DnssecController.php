<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{DomainRepository, ModuleResultRepository};
use DomainScope\Support\{Request, Response, Settings};

final class DnssecController extends SectionController
{
    protected function section(): string
    {
        return 'dnssec';
    }

    protected function sectionTitle(): string
    {
        return 'DNSSEC & Delegation';
    }

    protected function basePath(): string
    {
        return '/dnssec';
    }

    public function index(Request $r): Response
    {
        if (($redirect = $this->redirectIfDomainInput($r)) !== null) {
            return $redirect;
        }
        return $this->page('dnssec', [
            'title' => 'DNSSEC & Delegation', 'section' => 'dnssec', 'breadcrumbs' => [['DNSSEC & Delegation']],
            'domains' => DomainRepository::all(), 'results' => ModuleResultRepository::latestForAll('dnssec'),
            'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    public function show(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $id = (int) $domain['id'];
        $res = ModuleResultRepository::latest($id, 'dnssec');
        if ($res === null) {
            (new \DomainScope\Jobs\ModuleRunner())->run($domain, 'dnssec');
            $res = ModuleResultRepository::latest($id, 'dnssec');
        }
        $body = $this->render('partials/dnssec_report', ['domain' => $domain, 'dnssec' => $res, 'staleHours' => Settings::int('stale_hours') ?: 48]);
        return $this->domainPage($domain, $body, ['scripts' => ['domain-explorer.js']]);
    }

    public function run(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        return $domain === null ? $this->notFound('Domain') : $this->runAndRedirect($domain, 'dnssec');
    }
}

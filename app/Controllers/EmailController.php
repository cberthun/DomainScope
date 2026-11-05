<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{DomainRepository, ModuleResultRepository};
use DomainScope\Support\{Request, Response, Settings};

final class EmailController extends SectionController
{
    protected function section(): string
    {
        return 'email';
    }

    protected function sectionTitle(): string
    {
        return 'E-Mail-Sicherheit';
    }

    protected function basePath(): string
    {
        return '/email';
    }

    public function index(Request $r): Response
    {
        if (($redirect = $this->redirectIfDomainInput($r)) !== null) {
            return $redirect;
        }
        return $this->page('email', [
            'title' => 'E-Mail-Sicherheit', 'section' => 'email', 'breadcrumbs' => [['E-Mail-Sicherheit']],
            'domains' => DomainRepository::all(), 'results' => ModuleResultRepository::latestForAll('email'),
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
        $email = ModuleResultRepository::latest($id, 'email');
        if ($email === null) {
            (new \DomainScope\Jobs\ModuleRunner())->run($domain, 'email');
            $email = ModuleResultRepository::latest($id, 'email');
        }
        $body = $this->render('partials/email_report', ['domain' => $domain, 'email' => $email, 'staleHours' => Settings::int('stale_hours') ?: 48]);
        return $this->domainPage($domain, $body, ['scripts' => ['domain-explorer.js']]);
    }

    public function run(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $sel = $this->listInput('selectors');
        if ($r->post !== []) {
            DomainRepository::setSelectors((int) $domain['id'], implode(',', array_slice($sel, 0, 20)));
            $domain['dkim_selectors'] = implode(',', array_slice($sel, 0, 20));
        }
        return $this->runAndRedirect($domain, 'email', ['dkim_autoscan' => $r->str('autoscan') === '1']);
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{CertificateRepository, DomainRepository};
use DomainScope\Support\{Request, Response, Settings};
use DomainScope\Validation\Target;

final class TlsController extends SectionController
{
    protected function section(): string
    {
        return 'tls';
    }

    protected function sectionTitle(): string
    {
        return 'SSL/TLS-Zertifikate';
    }

    protected function basePath(): string
    {
        return '/tls';
    }

    public function index(Request $r): Response
    {
        if (($redirect = $this->redirectIfDomainInput($r)) !== null) {
            return $redirect;
        }
        return $this->page('tls', [
            'title' => 'SSL/TLS-Zertifikate', 'section' => 'tls', 'breadcrumbs' => [['SSL/TLS-Zertifikate']],
            'checks' => CertificateRepository::latestForAll(), 'warn' => Settings::days('cert_warn_days'),
            'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    /** Einzelner Host (beliebige Subdomain): Domain anlegen, Host prüfen, zur Domain-Seite. */
    public function check(Request $r): Response
    {
        $t = Target::parse($r->str('host'));
        if (!$t->isDomain() || $t->registrable === null) {
            $this->flash('error', $t->error ?? 'Bitte einen Hostnamen angeben.');
            return $this->redirect('/tls');
        }
        $domain = DomainRepository::ensure($t);
        $res = (new \DomainScope\Jobs\ModuleRunner())->run($domain, 'tls', ['host' => $t->host, 'port' => $r->int('port', 443) ?: 443]);
        $this->flash($res['ok'] ? 'success' : 'error', 'TLS: ' . $res['message']);
        return $this->redirect('/tls/' . rawurlencode($domain['name']));
    }

    public function show(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $id = (int) $domain['id'];
        $checks = CertificateRepository::latestForDomain($id);
        if ($checks === []) {
            (new \DomainScope\Jobs\ModuleRunner())->run($domain, 'tls');
            $checks = CertificateRepository::latestForDomain($id);
        }
        $body = $this->render('partials/tls_report', ['domain' => $domain, 'checks' => $checks, 'staleHours' => Settings::int('stale_hours') ?: 48]);
        return $this->domainPage($domain, $body, ['scripts' => ['domain-explorer.js']]);
    }

    public function run(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $opts = [];
        if ($r->str('host') !== '') {
            $t = Target::parse($r->str('host'));
            if ($t->isDomain() && ($t->host === $domain['name'] || str_ends_with((string) $t->host, '.' . $domain['name']))) {
                $opts['host'] = $t->host;
                $opts['port'] = $r->int('port', 443) ?: 443;
            }
        }
        return $this->runAndRedirect($domain, 'tls', $opts);
    }
}

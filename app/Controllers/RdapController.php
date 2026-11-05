<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\RegistrationRepository;
use DomainScope\Support\{Request, Response, Settings};

final class RdapController extends SectionController
{
    protected function section(): string
    {
        return 'rdap';
    }

    protected function sectionTitle(): string
    {
        return 'RDAP & WHOIS';
    }

    protected function basePath(): string
    {
        return '/rdap';
    }

    public function index(Request $r): Response
    {
        if (($redirect = $this->redirectIfDomainInput($r)) !== null) {
            return $redirect;
        }
        return $this->page('rdap', [
            'title' => 'RDAP & WHOIS', 'section' => 'rdap', 'breadcrumbs' => [['RDAP & WHOIS']],
            'rows' => RegistrationRepository::latestForAll(), 'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    public function show(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        if ($domain === null) {
            return $this->notFound('Domain');
        }
        $reg = RegistrationRepository::latest((int) $domain['id']);
        $notice = null;
        if ($reg === null) {
            $res = (new \DomainScope\Jobs\ModuleRunner())->run($domain, 'registration');
            $reg = RegistrationRepository::latest((int) $domain['id']);
            if (!$res['ok']) {
                $notice = $res['message'];
            }
        }
        $body = ($notice ? '<div class="alert alert-warn"><strong>Abruf nicht möglich:</strong> ' . e($notice) . '<br><span class="small">Mögliche Ursachen: nicht unterstützte TLD, Rate-Limit des Registrys, Domain nicht registriert oder Server nicht erreichbar. Es werden keine Ersatzdaten erfunden.</span></div>' : '')
            . $this->render('partials/registration_report', [
                'domain' => $domain, 'registration' => $reg, 'history' => RegistrationRepository::history((int) $domain['id'], 10),
                'staleHours' => Settings::int('stale_hours') ?: 48,
            ]);
        return $this->domainPage($domain, $body);
    }

    public function refresh(Request $r): Response
    {
        $domain = $this->domainOrCreate();
        return $domain === null ? $this->notFound('Domain') : $this->runAndRedirect($domain, 'registration');
    }
}

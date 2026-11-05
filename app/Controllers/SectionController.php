<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Jobs\ModuleRunner;
use DomainScope\Repositories\DomainRepository;
use DomainScope\Support\{Request, Response, Settings, View};
use DomainScope\Validation\Target;

/** Gemeinsame Logik der domainbezogenen Analyseseiten (E-Mail, TLS, DNSSEC, RDAP, Subdomains). */
abstract class SectionController extends Controller
{
    abstract protected function section(): string;

    abstract protected function sectionTitle(): string;

    abstract protected function basePath(): string;

    /** Leitet eine Domain-Eingabe (?domain=…) auf die Detailseite weiter. */
    protected function redirectIfDomainInput(Request $r): ?Response
    {
        $input = $r->str('domain');
        if ($input === '') {
            return null;
        }
        $t = Target::parse($input);
        if ($t->isIp()) {
            return $this->redirect('/ip/' . rawurlencode((string) $t->host));
        }
        if (!$t->valid() || $t->registrable === null) {
            $this->flash('error', $t->error ?? 'Ungültige Domain.');
            return $this->redirect($this->basePath());
        }
        $domain = DomainRepository::ensure($t);
        return $this->redirect($this->basePath() . '/' . rawurlencode($domain['name']));
    }

    /** Domain aus der Route; neue (gültige) Domains werden angelegt. @return array<string,mixed>|null */
    protected function domainOrCreate(): ?array
    {
        $domain = $this->domainFromRoute();
        if ($domain !== null) {
            return $domain;
        }
        $t = Target::parse((string) ($this->request->params['domain'] ?? ''));
        return ($t->isDomain() && $t->registrable !== null) ? DomainRepository::ensure($t) : null;
    }

    /** @param array<string,mixed> $domain */
    protected function runAndRedirect(array $domain, string $module, array $opts = []): Response
    {
        $res = (new ModuleRunner())->run($domain, $module, $opts);
        if ($this->request->isAjax()) {
            return $this->json(['ok' => $res['ok'], 'status' => $res['status'], 'message' => $res['message']]);
        }
        $this->flash($res['ok'] ? 'success' : 'error', ModuleRunner::MODULES[$module] . ': ' . $res['message']);
        return $this->redirect($this->basePath() . '/' . rawurlencode($domain['name']));
    }

    /** @param array<string,mixed> $domain */
    protected function domainPage(array $domain, string $bodyHtml, array $extra = []): Response
    {
        return $this->page('section_domain', $extra + [
            'title' => $this->sectionTitle() . ': ' . $domain['unicode_name'], 'section' => $this->section(),
            'breadcrumbs' => [[$this->sectionTitle(), $this->basePath()], [$domain['unicode_name']]],
            'domain' => $domain, 'body' => $bodyHtml, 'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    protected function render(string $partial, array $data): string
    {
        return View::partial($partial, $data);
    }
}

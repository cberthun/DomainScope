<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{DnsSnapshotRepository, DomainRepository};
use DomainScope\Services\DNS\{DnsExplorerService, DnsTypes, DohClient};
use DomainScope\Support\{Config, Request, Response};
use DomainScope\Validation\{DomainName, IpClassifier, Target};

final class DnsController extends Controller
{
    public function index(Request $r): Response
    {
        $name = $r->str('name');
        $data = ['title' => 'DNS Explorer', 'section' => 'dns', 'breadcrumbs' => [['DNS Explorer']], 'scripts' => ['dns-explorer.js'],
            'form' => $this->formState($r), 'lookup' => null, 'error' => null, 'registrable' => null, 'query' => []];
        if ($name !== '') {
            $q = $this->prepare($r, $name);
            if (isset($q['error'])) {
                $data['error'] = $q['error'];
            } else {
                $lookup = (new DnsExplorerService(new DohClient()))->lookup($q['name'], $data['form']['types'], $data['form']['resolvers'], $data['form']['flags']);
                $data['lookup'] = $lookup;
                $data['registrable'] = $q['registrable'];
                $data['query'] = ['name' => $q['name'], 'types' => implode(',', $data['form']['types']), 'resolvers' => implode(',', $data['form']['resolvers']), 'do' => $data['form']['flags']['do'] ? '1' : '', 'cd' => $data['form']['flags']['cd'] ? '1' : ''];
                \DomainScope\Support\DataSources::flush();
            }
        }
        return $this->page('dns', $data);
    }

    public function export(Request $r): Response
    {
        $q = $this->prepare($r, $r->str('name'));
        if (isset($q['error'])) {
            return new Response($q['error'], 400, ['Content-Type' => 'text/plain; charset=utf-8']);
        }
        $form = $this->formState($r);
        $lookup = (new DnsExplorerService(new DohClient()))->lookup($q['name'], $form['types'], $form['resolvers'], $form['flags']);
        $slug = preg_replace('/[^a-z0-9._-]+/i', '_', $q['name']);
        if ($r->str('format') === 'csv') {
            $rows = DnsExplorerService::flatten($lookup);
            return Response::download(DnsExplorerService::toCsv($rows, ['resolver', 'query_type', 'section', 'name', 'type', 'ttl', 'data', 'rcode', 'ms']), "dns_{$slug}.csv", 'text/csv; charset=utf-8');
        }
        $export = $lookup;
        foreach ($export['results'] as &$byType) {
            foreach ($byType as &$res) {
                unset($res['raw']);
            }
        }
        return Response::download(json_out($export, JSON_PRETTY_PRINT), "dns_{$slug}.json", 'application/json; charset=utf-8');
    }

    public function snapshots(Request $r): Response
    {
        $t = Target::parse($r->str('domain'));
        $domain = $t->isDomain() && $t->registrable ? DomainRepository::find($t->registrable) : null;
        if ($domain === null) {
            return $this->page('dns_snapshots', ['title' => 'DNS-Snapshots', 'section' => 'dns', 'breadcrumbs' => [['DNS Explorer', '/dns'], ['Snapshots']], 'domain' => null,
                'domains' => DomainRepository::all(), 'snapshots' => []]);
        }
        return $this->page('dns_snapshots', [
            'title' => 'DNS-Snapshots', 'section' => 'dns', 'domain' => $domain, 'domains' => DomainRepository::all(),
            'breadcrumbs' => [['DNS Explorer', '/dns'], ['Snapshots: ' . $domain['unicode_name']]],
            'snapshots' => DnsSnapshotRepository::list((int) $domain['id'], null, 60),
        ]);
    }

    public function compare(Request $r): Response
    {
        $a = DnsSnapshotRepository::find($r->int('a'));
        $b = DnsSnapshotRepository::find($r->int('b'));
        if ($a === null || $b === null || $a['domain_id'] !== $b['domain_id']) {
            return $this->notFound('Snapshot');
        }
        if ((int) $a['id'] > (int) $b['id']) {
            [$a, $b] = [$b, $a];
        }
        $same = $a['id'] === $b['id'];
        $diff = $same ? ['added' => [], 'removed' => []] : DnsSnapshotRepository::diff((int) $a['id'], (int) $b['id']);
        return $this->page('dns_compare', [
            'title' => 'Snapshot-Vergleich', 'section' => 'dns', 'a' => $a, 'b' => $b, 'diff' => $diff, 'same' => $same,
            'records' => $same ? DnsSnapshotRepository::records((int) $a['id']) : [],
            'breadcrumbs' => [['DNS Explorer', '/dns'], ['Snapshots', '/dns/snapshots?domain=' . rawurlencode($a['domain_name'])], ['Vergleich']],
        ]);
    }

    /** @return array{types:string[],resolvers:string[],flags:array{do:bool,cd:bool}} */
    private function formState(Request $r): array
    {
        $types = $this->listInput('types') ?: ['A', 'AAAA', 'MX', 'NS', 'TXT'];
        $types = array_values(array_intersect(array_map('strtoupper', $types), DnsTypes::EXPLORER));
        $resolvers = $this->listInput('resolvers') ?: [(string) Config::get('app.dns.default_resolver')];
        $resolvers = array_values(array_intersect($resolvers, array_keys((array) Config::get('app.dns.resolvers'))));
        return ['types' => $types ?: ['A'], 'resolvers' => $resolvers ?: [(string) Config::get('app.dns.default_resolver')],
            'flags' => ['do' => $r->str('do') === '1', 'cd' => $r->str('cd') === '1']];
    }

    /** @return array{name:string,registrable:?string}|array{error:string} */
    private function prepare(Request $r, string $input): array
    {
        $t = Target::parse($input);
        if ($t->isIp()) {
            return ['name' => (string) $t->host, 'registrable' => null];
        }
        // Namen mit Unterstrich (_dmarc, _domainkey …) zulassen
        $ascii = $t->isDomain() ? $t->host : DomainName::normalize(trim(preg_replace('#^[a-z]+://#i', '', $input) ?? ''), true);
        if ($ascii === null) {
            return ['error' => $t->error ?? 'Ungültiger Name.'];
        }
        if (!$t->valid()) {
            $reg = \DomainScope\Validation\PublicSuffix::registrable($ascii);
            return ['name' => $ascii, 'registrable' => $reg];
        }
        return ['name' => $ascii, 'registrable' => $t->registrable];
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Support\{Database, Request, Response};
use DomainScope\Validation\Target;

final class SearchController extends Controller
{
    /** Globale Suche: gültige Domain/URL/IP → direkt zur Ansicht, sonst Trefferliste. */
    public function go(Request $r): Response
    {
        $q = $r->str('q');
        if ($q === '') {
            return $this->redirect('/domains');
        }
        $t = Target::parse($q);
        if ($t->isIp()) {
            return $this->redirect('/ip/' . rawurlencode((string) $t->host));
        }
        if ($t->isDomain() && $t->registrable !== null && str_contains($q, '.')) {
            $domain = \DomainScope\Repositories\DomainRepository::ensure($t);
            return $this->redirect(url('/domain/' . rawurlencode($domain['name']), $t->isSubdomain ? ['host' => $t->host] : []));
        }
        $hits = $this->hits($q);
        return $this->page('search', ['title' => 'Suche', 'section' => '', 'breadcrumbs' => [['Suche']], 'q' => $q, 'hits' => $hits, 'target' => $t]);
    }

    public function suggest(Request $r): Response
    {
        $q = $r->str('q');
        if (mb_strlen($q) < 2) {
            return $this->json(['items' => []]);
        }
        $items = [];
        $t = Target::parse($q);
        if ($t->isIp()) {
            $items[] = ['label' => 'IP analysieren: ' . $t->host, 'url' => '/ip/' . rawurlencode((string) $t->host), 'type' => 'IP'];
        } elseif ($t->isDomain() && $t->registrable !== null) {
            $items[] = ['label' => 'Analysieren: ' . ($t->unicode ?? $t->host), 'url' => '/search?q=' . rawurlencode($q), 'type' => 'Neu'];
        }
        foreach ($this->hits($q, 4) as $group => $rows) {
            foreach ($rows as $row) {
                $items[] = $row + ['type' => $group];
            }
        }
        return $this->json(['items' => array_slice($items, 0, 14)]);
    }

    /** @return array<string,array<int,array{label:string,url:string,sub?:string}>> */
    private function hits(string $q, int $limit = 15): array
    {
        $like = '%' . addcslashes($q, '%_\\') . '%';
        $out = [];
        foreach (Database::all('SELECT name, unicode_name FROM domains WHERE name LIKE ? OR unicode_name LIKE ? ORDER BY name LIMIT ' . $limit, [$like, $like]) as $d) {
            $out['Domain'][] = ['label' => $d['unicode_name'], 'url' => '/domain/' . rawurlencode($d['name'])];
        }
        foreach (Database::all('SELECT s.hostname, d.name FROM subdomains s JOIN domains d ON d.id = s.domain_id WHERE s.hostname LIKE ? ORDER BY s.hostname LIMIT ' . $limit, [$like]) as $s) {
            $out['Subdomain'][] = ['label' => $s['hostname'], 'url' => '/domain/' . rawurlencode($s['name']) . '?tab=subdomains&host=' . rawurlencode($s['hostname'])];
        }
        foreach (Database::all('SELECT address, as_name FROM ip_addresses WHERE address LIKE ? OR reverse_dns LIKE ? OR as_name LIKE ? ORDER BY address LIMIT ' . $limit, [$like, $like, $like]) as $i) {
            $out['IP'][] = ['label' => $i['address'], 'url' => '/ip/' . rawurlencode($i['address']), 'sub' => (string) $i['as_name']];
        }
        foreach (Database::all('SELECT id, name, type FROM assets WHERE name LIKE ? OR address LIKE ? OR tags LIKE ? ORDER BY name LIMIT ' . $limit, [$like, $like, $like]) as $a) {
            $out['Asset'][] = ['label' => $a['name'], 'url' => '/inventory/' . (int) $a['id'], 'sub' => $a['type']];
        }
        foreach (Database::all('SELECT id, title FROM findings WHERE title LIKE ? OR subject LIKE ? ORDER BY id DESC LIMIT ' . $limit, [$like, $like]) as $f) {
            $out['Finding'][] = ['label' => $f['title'], 'url' => '/findings/' . (int) $f['id']];
        }
        return $out;
    }
}

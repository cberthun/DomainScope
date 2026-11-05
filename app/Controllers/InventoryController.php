<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{ActivityRepository, AssetRepository, DomainRepository, IpRepository};
use DomainScope\Services\DNS\RecordFormatter;
use DomainScope\Support\{Database, Request, Response};

final class InventoryController extends Controller
{
    public function index(Request $r): Response
    {
        $f = ['type' => $r->str('type'), 'environment' => $r->str('environment'), 'q' => $r->str('q')];
        return $this->page('inventory', [
            'title' => 'Infrastruktur-Inventar', 'section' => 'inventory', 'breadcrumbs' => [['Infrastruktur-Inventar']], 'scripts' => ['graph.js'],
            'assets' => AssetRepository::all($f), 'filter' => $f, 'relCount' => count(AssetRepository::relationships()),
            'unconfirmed' => (int) Database::value('SELECT COUNT(*) FROM asset_relationships WHERE confirmed = 0'),
        ]);
    }

    public function form(Request $r): Response
    {
        $id = (int) ($r->params['id'] ?? 0);
        $asset = $id ? AssetRepository::find($id) : null;
        if ($id && $asset === null) {
            return $this->notFound('Asset');
        }
        $preset = $asset ?? ['name' => $r->str('name'), 'type' => $r->str('type', 'server'), 'address' => $r->str('address'), 'environment' => 'production', 'domain_id' => null,
            'description' => '', 'provider' => '', 'tags' => '', 'notes' => ''];
        return $this->page('inventory_form', [
            'title' => $asset ? 'Asset bearbeiten' : 'Neues Asset', 'section' => 'inventory',
            'breadcrumbs' => [['Infrastruktur-Inventar', '/inventory'], [$asset ? $asset['name'] : 'Neu']],
            'asset' => $asset, 'preset' => $preset, 'domains' => DomainRepository::all(), 'errors' => [],
        ]);
    }

    public function store(Request $r): Response
    {
        return $this->save(null, $r);
    }

    public function update(Request $r): Response
    {
        return $this->save((int) $r->params['id'], $r);
    }

    private function save(?int $id, Request $r): Response
    {
        $d = $r->post;
        if (trim((string) ($d['name'] ?? '')) === '') {
            $this->flash('error', 'Der Name darf nicht leer sein.');
            return $this->redirect($id ? "/inventory/$id/edit" : '/inventory/new');
        }
        if ($id) {
            if (AssetRepository::find($id) === null) {
                return $this->notFound('Asset');
            }
            AssetRepository::update($id, $d);
            $this->flash('success', 'Asset gespeichert.');
        } else {
            $id = AssetRepository::create($d);
            ActivityRepository::log('inventory', 'Asset ' . mb_substr((string) $d['name'], 0, 100) . ' angelegt');
            $this->flash('success', 'Asset angelegt.');
        }
        return $this->redirect("/inventory/$id");
    }

    public function show(Request $r): Response
    {
        $asset = AssetRepository::find((int) $r->params['id']);
        if ($asset === null) {
            return $this->notFound('Asset');
        }
        $rels = AssetRepository::relationships((int) $asset['id']);
        $linkedDomain = $asset['domain_id'] ? DomainRepository::findById((int) $asset['domain_id']) : null;
        return $this->page('inventory_show', [
            'title' => $asset['name'], 'section' => 'inventory', 'breadcrumbs' => [['Infrastruktur-Inventar', '/inventory'], [$asset['name']]],
            'asset' => $asset, 'rels' => $rels, 'others' => array_filter(AssetRepository::all(), static fn($a) => (int) $a['id'] !== (int) $asset['id']),
            'linkedDomain' => $linkedDomain, 'scripts' => ['graph.js'],
        ]);
    }

    public function delete(Request $r): Response
    {
        AssetRepository::delete((int) $r->params['id']);
        $this->flash('success', 'Asset gelöscht.');
        return $this->redirect('/inventory');
    }

    public function link(Request $r): Response
    {
        $from = (int) $r->params['id'];
        $to = $r->int('to');
        $dir = $r->str('direction', 'out');
        if (AssetRepository::find($to) === null) {
            $this->flash('error', 'Zielasset nicht gefunden.');
        } else {
            [$a, $b] = $dir === 'in' ? [$to, $from] : [$from, $to];
            $this->flash(AssetRepository::link($a, $b, $r->str('relation', 'depends_on'), 'manual', true, $r->str('note') ?: null) ? 'success' : 'warn', 'Beziehung gespeichert (manuell bestätigt).');
        }
        return $this->redirect("/inventory/$from");
    }

    public function confirmLink(Request $r): Response
    {
        AssetRepository::confirm((int) $r->params['rid']);
        return $this->redirect($r->str('back', '/inventory'));
    }

    public function unlink(Request $r): Response
    {
        AssetRepository::unlink((int) $r->params['rid']);
        return $this->redirect($r->str('back', '/inventory'));
    }

    /** Übernimmt beobachtete Daten (Domains, IPs, Nameserver, MX) als Assets; Beziehungen bleiben unbestätigt. */
    public function import(Request $r): Response
    {
        $created = 0;
        $rels = 0;
        $get = function (string $type, string $name, string $address, ?int $domainId = null, string $desc = '') use (&$created): int {
            $a = AssetRepository::findByAddress($type, $address);
            if ($a) {
                return (int) $a['id'];
            }
            $created++;
            return AssetRepository::create(['name' => $name, 'type' => $type, 'address' => $address, 'domain_id' => $domainId, 'description' => $desc, 'tags' => 'automatisch erkannt']);
        };
        foreach (DomainRepository::all() as $d) {
            $did = $get('domain', $d['unicode_name'], $d['name'], (int) $d['id'], 'Automatisch aus gespeicherten Domains übernommen');
            $snap = \DomainScope\Repositories\DnsSnapshotRepository::latest((int) $d['id'], $d['name'], (string) cfg('app.dns.default_resolver'));
            if ($snap) {
                foreach (\DomainScope\Repositories\DnsSnapshotRepository::records((int) $snap['id']) as $rec) {
                    if ($rec['type'] === 'NS') {
                        $nid = $get('nameserver', $rec['data'], $rec['data'], null, 'Nameserver laut DNS');
                        $rels += AssetRepository::link($did, $nid, 'delegated_to', 'observed', false, 'aus NS-Record') ? 1 : 0;
                    } elseif ($rec['type'] === 'MX' && ($mx = RecordFormatter::parseMx($rec['data'])) !== null && $mx['host'] !== '') {
                        $mid = $get('mailserver', $mx['host'], $mx['host'], null, 'Mailserver laut MX-Record');
                        $rels += AssetRepository::link($did, $mid, 'mail_via', 'observed', false, 'aus MX-Record') ? 1 : 0;
                    }
                }
            }
            $seen = [];
            foreach (IpRepository::forDomain((int) $d['id']) as $ip) {
                if ($ip['hostname'] !== $d['name'] || isset($seen[$ip['address']])) {
                    continue;
                }
                $seen[$ip['address']] = true;
                $iid = $get('ip', $ip['address'], $ip['address'], null, trim(($ip['as_name'] ?? '') . ($ip['asn'] ? ' (AS' . $ip['asn'] . ')' : '')));
                $rels += AssetRepository::link($did, $iid, 'resolves_to', 'observed', false, 'aus ' . $ip['record_type'] . '-Record') ? 1 : 0;
            }
        }
        ActivityRepository::log('inventory', "Inventar-Import: $created Assets, $rels Beziehungen (unbestätigt)");
        $this->flash('success', "$created neue Assets und $rels neue (unbestätigte) Beziehungen übernommen.");
        return $this->redirect('/inventory');
    }

    public function graph(Request $r): Response
    {
        $nodes = array_map(static fn($a) => [
            'id' => (int) $a['id'], 'name' => $a['name'], 'type' => $a['type'], 'env' => $a['environment'], 'address' => $a['address'],
        ], AssetRepository::all());
        $edges = array_map(static fn($e) => [
            'id' => (int) $e['id'], 'from' => (int) $e['from_asset_id'], 'to' => (int) $e['to_asset_id'],
            'relation' => AssetRepository::RELATIONS[$e['relation']] ?? $e['relation'], 'origin' => $e['origin'], 'confirmed' => (bool) $e['confirmed'],
        ], AssetRepository::relationships((int) $r->int('focus')));
        if ($r->int('focus')) {
            $ids = [$r->int('focus')];
            foreach ($edges as $e) {
                $ids[] = $e['from'];
                $ids[] = $e['to'];
            }
            $nodes = array_values(array_filter($nodes, static fn($n) => in_array($n['id'], $ids, true)));
        }
        return $this->json(['nodes' => $nodes, 'edges' => $edges, 'types' => AssetRepository::TYPES]);
    }
}

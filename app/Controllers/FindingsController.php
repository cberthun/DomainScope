<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Findings\FindingsEngine;
use DomainScope\Repositories\{DomainRepository, FindingRepository};
use DomainScope\Support\{Request, Response};

final class FindingsController extends Controller
{
    public function index(Request $r): Response
    {
        $filter = [
            'status' => $r->has('status') ? $r->str('status') : 'active', 'severity' => $r->str('severity'),
            'module' => $r->str('module'), 'domain_id' => $r->int('domain_id'), 'q' => $r->str('q'),
        ];
        return $this->page('findings', [
            'title' => 'Findings', 'section' => 'findings', 'breadcrumbs' => [['Findings']],
            'findings' => FindingRepository::search($filter), 'filter' => $filter, 'domains' => DomainRepository::all(),
            'counts' => FindingRepository::countsBySeverity(), 'rules' => FindingsEngine::RULES,
        ]);
    }

    public function show(Request $r): Response
    {
        $f = FindingRepository::find((int) $r->params['id']);
        if ($f === null) {
            return $this->notFound('Finding');
        }
        return $this->page('finding', [
            'title' => $f['title'], 'section' => 'findings', 'breadcrumbs' => [['Findings', '/findings'], [mb_strimwidth($f['title'], 0, 50, '…')]],
            'f' => $f, 'events' => FindingRepository::events((int) $f['id']),
        ]);
    }

    public function status(Request $r): Response
    {
        $id = (int) $r->params['id'];
        $ok = FindingRepository::setStatus($id, $r->str('status'), $r->str('note') ?: null);
        $this->flash($ok ? 'success' : 'error', $ok ? 'Status aktualisiert.' : 'Ungültiger Status.');
        return $this->redirect('/findings/' . $id);
    }
}

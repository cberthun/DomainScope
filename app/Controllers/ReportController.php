<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\DomainRepository;
use DomainScope\Services\DNS\DnsExplorerService;
use DomainScope\Services\Reports\ReportBuilder;
use DomainScope\Support\{Request, Response, View};

final class ReportController extends Controller
{
    public function index(Request $r): Response
    {
        return $this->page('reports', [
            'title' => 'Berichte', 'section' => 'reports', 'breadcrumbs' => [['Berichte']],
            'types' => ReportBuilder::TYPES, 'domains' => DomainRepository::all(),
        ]);
    }

    public function show(Request $r): Response
    {
        $type = (string) $r->params['type'];
        if (!isset(ReportBuilder::TYPES[$type])) {
            return $this->notFound('Bericht');
        }
        $domain = null;
        if ($type !== 'inventory') {
            $domain = $this->domainFromRoute();
            if ($domain === null) {
                return $this->notFound('Domain');
            }
        }
        $report = (new ReportBuilder())->build($type, $domain);
        $slug = $type . '_' . ($domain['name'] ?? 'alle') . '_' . gmdate('Ymd_His');
        switch ($r->str('format', 'html')) {
            case 'json':
                return Response::download(json_out($report, JSON_PRETTY_PRINT), $slug . '.json', 'application/json; charset=utf-8');
            case 'csv':
                $fh = fopen('php://temp', 'r+');
                fwrite($fh, "\xEF\xBB\xBF");
                foreach ($report['sections'] as $s) {
                    fputcsv($fh, ['# ' . $s['title']], ',', '"', '\\');
                    fputcsv($fh, $s['columns'], ',', '"', '\\');
                    foreach ($s['rows'] as $row) {
                        fputcsv($fh, array_map(static fn($v) => ($v !== '' && in_array(((string) $v)[0] ?? '', ['=', '+', '-', '@'], true)) ? "'" . $v : (string) $v, $row), ',', '"', '\\');
                    }
                    fputcsv($fh, [], ',', '"', '\\');
                }
                rewind($fh);
                return Response::download((string) stream_get_contents($fh), $slug . '.csv', 'text/csv; charset=utf-8');
            default:
                return Response::html(View::partial('layouts/report', ['report' => $report, 'print' => $r->str('print') === '1']));
        }
    }
}

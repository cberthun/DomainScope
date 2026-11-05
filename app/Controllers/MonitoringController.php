<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Jobs\ModuleRunner;
use DomainScope\Repositories\{ActivityRepository, DomainRepository};
use DomainScope\Support\{Database, Request, Response, Settings};

final class MonitoringController extends Controller
{
    public function index(Request $r): Response
    {
        $type = $r->str('type');
        $domainId = $r->int('domain_id') ?: null;
        $jobs = Database::all('SELECT j.*, d.name AS domain_name FROM scan_jobs j LEFT JOIN domains d ON d.id = j.domain_id ORDER BY j.id DESC LIMIT 25');
        foreach ($jobs as &$j) {
            $j['results'] = Database::all('SELECT module, status, message, duration_ms FROM scan_results WHERE job_id = ? ORDER BY id', [$j['id']]);
        }
        unset($j);
        $lastCron = Database::one("SELECT * FROM scan_jobs WHERE trigger_type = 'cron' ORDER BY id DESC LIMIT 1");
        return $this->page('monitoring', [
            'title' => 'Monitoring & Verlauf', 'section' => 'monitoring', 'breadcrumbs' => [['Monitoring & Verlauf']], 'scripts' => ['domain-explorer.js'],
            'domains' => DomainRepository::all(), 'changes' => ActivityRepository::changes($domainId, 80, $type ?: null), 'jobs' => $jobs,
            'lastCron' => $lastCron, 'staleHours' => Settings::int('stale_hours') ?: 48, 'type' => $type, 'domainId' => $domainId,
            'snapCount' => (int) Database::value('SELECT COUNT(*) FROM dns_snapshots'), 'phpBin' => PHP_BINARY,
            'root' => dirname(__DIR__, 2),
        ]);
    }

    public function run(Request $r): Response
    {
        $domain = DomainRepository::find($r->str('domain'));
        if ($domain === null) {
            $this->flash('error', 'Domain nicht gefunden.');
            return $this->redirect('/monitoring');
        }
        if ($r->str('action') === 'toggle') {
            DomainRepository::setMonitored((int) $domain['id'], !$domain['monitored']);
            $this->flash('success', $domain['monitored'] ? 'Überwachung deaktiviert.' : 'Überwachung aktiviert.');
            return $this->redirect('/monitoring');
        }
        $res = (new ModuleRunner())->runAll($domain, 'manual');
        if ($r->isAjax()) {
            return $this->json(['ok' => $res['status'] !== 'failed', 'status' => $res['status'], 'message' => 'Prüfung ' . $domain['unicode_name'] . ': ' . ui_status_label($res['status'])]);
        }
        $this->flash($res['status'] === 'ok' ? 'success' : 'warn', 'Prüfung von ' . $domain['unicode_name'] . ': ' . ui_status_label($res['status']));
        return $this->redirect('/monitoring');
    }
}

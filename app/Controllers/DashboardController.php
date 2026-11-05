<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\{ActivityRepository, CertificateRepository, DomainRepository, FindingRepository, RegistrationRepository, StatsRepository};
use DomainScope\Support\{Request, Response, Settings};

final class DashboardController extends Controller
{
    public function index(Request $r): Response
    {
        $warn = Settings::days('cert_warn_days')[0] ?? 30;
        $stats = StatsRepository::dashboard($warn);
        $certs = array_filter(CertificateRepository::latestForAll(), static fn($c) => !empty($c['not_after']));
        $expiring = array_slice(array_filter($certs, static fn($c) => days_until($c['not_after'] . ' UTC') <= $warn), 0, 6);
        $domains = DomainRepository::all('checked');
        $regs = array_slice(array_filter(RegistrationRepository::latestForAll(), static fn($x) => !empty($x['expires_at']) && days_until($x['expires_at'] . ' UTC') <= 90), 0, 5);

        return $this->page('dashboard', [
            'title' => 'Dashboard', 'section' => 'dashboard', 'scripts' => ['charts.js'],
            'stats' => $stats, 'severity' => FindingRepository::countsBySeverity(),
            'problems' => array_slice(FindingRepository::search(['status' => 'active']), 0, 10),
            'timeline' => StatsRepository::timeline(14), 'jobs' => StatsRepository::recentJobs(6),
            'failed' => StatsRepository::failedResults(5), 'sources' => StatsRepository::dataSources(),
            'expiring' => $expiring, 'expiringDomains' => $regs, 'domains' => array_slice($domains, 0, 8),
            'activity' => ActivityRepository::recent(8), 'perDay' => StatsRepository::findingsPerDay(14),
            'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }
}

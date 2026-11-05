<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\IpRepository;
use DomainScope\Services\DNS\DohClient;
use DomainScope\Services\IPIntelligence\IpIntelligenceService;
use DomainScope\Support\{DataSources, Database, Request, Response, Settings};
use DomainScope\Validation\{IpClassifier, Target};

final class IpController extends Controller
{
    public function index(Request $r): Response
    {
        $q = $r->str('q');
        return $this->page('ips', [
            'title' => 'IP & ASN Intelligence', 'section' => 'ips', 'breadcrumbs' => [['IP & ASN Intelligence']],
            'ips' => IpRepository::all($q), 'q' => $q, 'staleHours' => Settings::int('stale_hours') ?: 48,
            'asns' => Database::all('SELECT asn, MAX(as_name) AS as_name, COUNT(*) AS n FROM ip_addresses WHERE asn IS NOT NULL GROUP BY asn ORDER BY n DESC LIMIT 10'),
        ]);
    }

    public function go(Request $r): Response
    {
        $t = Target::parse($r->str('ip'));
        if ($t->isIp()) {
            return $this->redirect('/ip/' . rawurlencode((string) $t->host));
        }
        if ($t->isDomain() && $t->registrable) {
            $this->flash('info', 'Domain erkannt – Domain-Detailansicht geöffnet.');
            return $this->redirect('/domain/' . rawurlencode($t->registrable) . ($t->isSubdomain ? '?host=' . rawurlencode((string) $t->host) : ''));
        }
        $this->flash('error', 'Bitte eine gültige IPv4- oder IPv6-Adresse eingeben.');
        return $this->redirect('/ips');
    }

    public function show(Request $r): Response
    {
        $ip = IpClassifier::normalize((string) $r->params['ip']);
        if ($ip === null) {
            return $this->notFound('IP-Adresse');
        }
        $row = IpRepository::find($ip);
        $fresh = $row && $row['checked_at'] && strtotime($row['checked_at'] . ' UTC') > time() - 86400;
        $error = null;
        if (!$fresh) {
            try {
                $info = (new IpIntelligenceService(new DohClient()))->lookup($ip);
                IpRepository::saveLookup($info);
                DataSources::flush();
                $row = IpRepository::find($ip);
            } catch (\Throwable $e) {
                $error = 'Abfrage fehlgeschlagen: ' . $e->getMessage();
            }
        }
        $cls = IpClassifier::classify($ip);
        $domains = $row ? IpRepository::domainsFor((int) $row['id']) : [];
        $tls = Database::all(
            'SELECT t.host, t.port, t.status, t.checked_at, c.not_after, c.fingerprint_sha256, d.name AS domain_name
             FROM tls_checks t JOIN domains d ON d.id = t.domain_id LEFT JOIN certificates c ON c.id = t.certificate_id
             JOIN (SELECT MAX(id) mid FROM tls_checks WHERE ip = ? GROUP BY domain_id, host, port) x ON x.mid = t.id ORDER BY t.host',
            [$ip]
        );
        return $this->page('ip', [
            'title' => $ip, 'section' => 'ips', 'breadcrumbs' => [['IP & ASN Intelligence', '/ips'], [$ip]],
            'ip' => $ip, 'row' => $row, 'cls' => $cls, 'domains' => $domains, 'tls' => $tls, 'error' => $error,
            'staleHours' => Settings::int('stale_hours') ?: 48,
        ]);
    }

    public function refresh(Request $r): Response
    {
        $ip = IpClassifier::normalize((string) $r->params['ip']);
        if ($ip === null) {
            return $this->notFound('IP-Adresse');
        }
        try {
            IpRepository::saveLookup((new IpIntelligenceService(new DohClient()))->lookup($ip));
            DataSources::flush();
            $this->flash('success', 'IP-Daten aktualisiert.');
        } catch (\Throwable $e) {
            $this->flash('error', 'Aktualisierung fehlgeschlagen: ' . $e->getMessage());
        }
        return $this->redirect('/ip/' . rawurlencode($ip));
    }
}

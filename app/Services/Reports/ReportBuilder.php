<?php
declare(strict_types=1);

namespace DomainScope\Services\Reports;

use DomainScope\Repositories\{ActivityRepository, AssetRepository, CertificateRepository, DnsSnapshotRepository, FindingRepository, IpRepository,
    ModuleResultRepository, RegistrationRepository, SubdomainRepository};
use DomainScope\Services\DNS\RecordFormatter;

/**
 * Erzeugt strukturierte Berichte (Abschnitte mit Tabellen) aus gespeicherten Daten.
 * Jeder Bericht enthält Datenquellen, Erstellungszeitpunkt und bekannte Einschränkungen.
 */
final class ReportBuilder
{
    public const TYPES = [
        'domain' => ['Domainbericht', 'Gesamtüberblick: Registrierung, DNS, E-Mail, TLS, DNSSEC, Subdomains, Findings'],
        'email' => ['E-Mail-Sicherheitsbericht', 'SPF, DKIM, DMARC, MX/PTR, MTA-STS, TLS-RPT, BIMI mit Begründung und Empfehlung'],
        'tls' => ['TLS-Bericht', 'Zertifikate, Laufzeiten, Kette, Protokoll'],
        'dns-changes' => ['DNS-Änderungsbericht', 'Erkannte Änderungen und Snapshot-Verlauf'],
        'inventory' => ['Infrastruktur-Inventarbericht', 'Alle Assets und Beziehungen (domainunabhängig)'],
    ];

    /** @param array<string,mixed>|null $domain @return array<string,mixed> */
    public function build(string $type, ?array $domain): array
    {
        $now = gmdate('Y-m-d H:i:s');
        $report = match ($type) {
            'domain' => $this->domainReport($domain),
            'email' => $this->emailReport($domain),
            'tls' => $this->tlsReport($domain),
            'dns-changes' => $this->dnsChangesReport($domain),
            'inventory' => $this->inventoryReport(),
            default => throw new \InvalidArgumentException('Unbekannter Berichtstyp'),
        };
        return $report + ['type' => $type, 'generated_at' => $now, 'domain' => $domain['name'] ?? null];
    }

    /** @return array<string,mixed> */
    private function domainReport(array $d): array
    {
        $id = (int) $d['id'];
        $sections = [];
        $reg = RegistrationRepository::latest($id);
        $sections[] = ['title' => 'Registrierung', 'columns' => ['Feld', 'Wert'], 'rows' => $reg ? [
            ['Registrar', $reg['registrar'] ?? '–'], ['Registriert', $reg['registered_at'] ?? '–'], ['Letzte Änderung', $reg['changed_at'] ?? '–'],
            ['Läuft ab', $reg['expires_at'] ?? '–'], ['Status', implode(', ', $reg['statuses'])], ['Nameserver (Registry)', implode(', ', $reg['nameservers'])],
            ['Quelle', strtoupper($reg['source']) . ' · ' . ($reg['source_url'] ?? '') . ' · abgerufen ' . $reg['fetched_at'] . ' UTC'],
        ] : [], 'note' => $reg ? null : 'Keine Registrierungsdaten gespeichert.'];

        $snap = DnsSnapshotRepository::latest($id, $d['name'], (string) cfg('app.dns.default_resolver'));
        $rows = [];
        if ($snap) {
            foreach (DnsSnapshotRepository::records((int) $snap['id']) as $r) {
                $rows[] = [$r['type'], $r['name'], (string) $r['ttl'], $r['data']];
            }
        }
        $sections[] = ['title' => 'DNS-Records (Snapshot ' . ($snap['taken_at'] ?? 'keiner') . ' UTC)', 'columns' => ['Typ', 'Name', 'TTL', 'Daten'], 'rows' => $rows];

        $sections = array_merge($sections, $this->emailSections($id), $this->tlsSections($id));

        $dn = ModuleResultRepository::latest($id, 'dnssec');
        if ($dn) {
            $a = $dn['data'];
            $sections[] = ['title' => 'DNSSEC (geprüft ' . $dn['checked_at'] . ' UTC)', 'columns' => ['Feld', 'Wert'], 'rows' => [
                ['Zustand', $a['state']], ['Validierung', $a['validation']['level']], ['DS-Records', (string) count($a['ds'])], ['DNSKEY-Records', (string) count($a['dnskey'])],
            ], 'note' => implode(' ', $a['limitations'])];
        }
        $subs = SubdomainRepository::forDomain($id);
        $sections[] = ['title' => 'Subdomains (passiv, Certificate Transparency)', 'columns' => ['Host', 'Status', 'IPs', 'Zuletzt gesehen'],
            'rows' => array_map(static fn($s) => [$s['hostname'], $s['status'] === 'present' ? 'gefunden' : 'nicht mehr gefunden', implode(' ', $s['resolved_ips']), $s['last_seen']], $subs),
            'note' => 'Ein passiver Fund beweist nicht, dass der Host aktuell existiert oder erreichbar ist.'];
        $sections[] = $this->findingsSection($id);
        return [
            'title' => 'Domainbericht ' . $d['unicode_name'],
            'sources' => ['DNS-over-HTTPS (Cloudflare, Google, Quad9)', 'RDAP (IANA-Bootstrap) / WHOIS', 'Certificate Transparency (crt.sh, Cert Spotter)', 'TLS-Handshake (PHP/OpenSSL)', 'Team Cymru IP-to-ASN'],
            'limitations' => ['Der Bericht beschreibt den Stand der zuletzt gespeicherten Prüfungen; zwischenzeitliche Änderungen sind nicht enthalten.', 'Fehlende Daten bedeuten nicht automatisch ein Sicherheitsproblem.'],
            'sections' => $sections,
        ];
    }

    /** @return array<string,mixed> */
    private function emailReport(array $d): array
    {
        $id = (int) $d['id'];
        $sections = $this->emailSections($id);
        $sections[] = $this->findingsSection($id, 'email');
        return [
            'title' => 'E-Mail-Sicherheitsbericht ' . $d['unicode_name'],
            'sources' => ['DNS-over-HTTPS (TXT/MX/A/AAAA/PTR)', 'MTA-STS-Policy über HTTPS', 'BIMI-Logo über HTTPS'],
            'limitations' => ['DKIM-Selektoren lassen sich nicht per DNS auflisten – nur angegebene Selektoren wurden geprüft.', 'SPF-Makros (z. B. exists:%{i}) werden nicht aufgelöst.', 'Es wurde keine Zustellung getestet.'],
            'sections' => $sections,
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private function emailSections(int $id): array
    {
        $res = ModuleResultRepository::latest($id, 'email');
        if (!$res) {
            return [['title' => 'E-Mail-Sicherheit', 'columns' => ['Hinweis'], 'rows' => [['Keine Prüfung gespeichert.']]]];
        }
        $rows = [];
        foreach ($res['data']['checks'] as $c) {
            $rows[] = [$c['title'], ui_status_label($c['status']), $c['summary'], $c['record'] ?? ''];
        }
        $out = [['title' => 'E-Mail-Sicherheit – Überblick (geprüft ' . $res['checked_at'] . ' UTC)', 'columns' => ['Prüfung', 'Status', 'Ergebnis', 'Record'], 'rows' => $rows]];
        $fr = [];
        foreach ($res['data']['checks'] as $c) {
            foreach ($c['findings'] as $f) {
                if ($f['level'] === 'pass') {
                    continue;
                }
                $fr[] = [$c['title'], $f['level'], $f['kind'] === 'bestpractice' ? 'Best Practice' : 'Technischer Befund', $f['message'], $f['impact'] ?? '', $f['recommendation'] ?? ''];
            }
        }
        $out[] = ['title' => 'E-Mail-Sicherheit – Befunde', 'columns' => ['Prüfung', 'Stufe', 'Art', 'Befund', 'Auswirkung', 'Empfehlung'], 'rows' => $fr];
        return $out;
    }

    /** @return array<string,mixed> */
    private function tlsReport(array $d): array
    {
        return [
            'title' => 'TLS-Bericht ' . $d['unicode_name'],
            'sources' => ['TLS-Handshake mit SNI (PHP/OpenSSL)', 'CA-Bundle (Mozilla/curl.se)'],
            'limitations' => ['Geprüft wird der Zustand zum Prüfzeitpunkt vom Standort dieses Servers aus.', 'Nicht erreichbare Hosts sind nicht als ungültig zu werten.'],
            'sections' => $this->tlsSections((int) $d['id']),
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private function tlsSections(int $id): array
    {
        $rows = [];
        foreach (CertificateRepository::latestForDomain($id) as $c) {
            $rows[] = [$c['host'] . ':' . $c['port'], $c['status'], $c['subject'] ?? '', $c['issuer'] ?? '', (string) ($c['not_after'] ?? ''),
                $c['not_after'] ? (string) days_until($c['not_after'] . ' UTC') : '', (string) $c['protocol'], (string) $c['fingerprint_sha256'], (string) $c['error']];
        }
        return [['title' => 'TLS-Zertifikate', 'columns' => ['Host', 'Status', 'Subject', 'Aussteller', 'Läuft ab (UTC)', 'Tage', 'Protokoll', 'SHA-256', 'Fehler'], 'rows' => $rows]];
    }

    /** @return array<string,mixed> */
    private function dnsChangesReport(array $d): array
    {
        $id = (int) $d['id'];
        $changes = array_map(static fn($c) => [$c['detected_at'], $c['type'], $c['summary']], ActivityRepository::changes($id, 500));
        $snaps = array_map(static fn($s) => [$s['taken_at'], $s['host'], $s['resolver'], (string) $s['record_count']], DnsSnapshotRepository::list($id, null, 100));
        return [
            'title' => 'DNS-Änderungsbericht ' . $d['unicode_name'],
            'sources' => ['Gespeicherte DNS-Snapshots (DoH)', 'Vergleich aufeinanderfolgender Snapshots'],
            'limitations' => ['Änderungen werden erst ab dem zweiten Snapshot erkannt.', 'TTL-Änderungen gelten nicht als Änderung.', 'Zwischen zwei Prüfungen aufgetretene Zwischenzustände sind nicht erfasst.'],
            'sections' => [
                ['title' => 'Erkannte Änderungen', 'columns' => ['Zeitpunkt (UTC)', 'Art', 'Beschreibung'], 'rows' => $changes],
                ['title' => 'Snapshot-Verlauf', 'columns' => ['Zeitpunkt (UTC)', 'Host', 'Resolver', 'Records'], 'rows' => $snaps],
            ],
        ];
    }

    /** @return array<string,mixed> */
    private function inventoryReport(): array
    {
        $assets = array_map(static fn($a) => [$a['name'], AssetRepository::TYPES[$a['type']] ?? $a['type'], (string) $a['address'], (string) $a['provider'],
            AssetRepository::ENVIRONMENTS[$a['environment']] ?? $a['environment'], (string) $a['tags'], (string) $a['domain_name'], (string) $a['description']], AssetRepository::all());
        $rels = array_map(static fn($e) => [$e['from_name'], AssetRepository::RELATIONS[$e['relation']] ?? $e['relation'], $e['to_name'], $e['confirmed'] ? 'manuell bestätigt' : 'automatisch beobachtet'], AssetRepository::relationships());
        return [
            'title' => 'Infrastruktur-Inventarbericht',
            'sources' => ['Manuell gepflegtes Inventar', 'Automatisch beobachtete Zuordnungen aus DNS-Snapshots'],
            'limitations' => ['Automatisch beobachtete Beziehungen sind unbestätigt, bis sie manuell bestätigt wurden.'],
            'sections' => [
                ['title' => 'Assets', 'columns' => ['Name', 'Typ', 'Adresse', 'Anbieter', 'Umgebung', 'Tags', 'Domain', 'Beschreibung'], 'rows' => $assets],
                ['title' => 'Beziehungen', 'columns' => ['Von', 'Beziehung', 'Nach', 'Herkunft'], 'rows' => $rels],
            ],
        ];
    }

    /** @return array<string,mixed> */
    private function findingsSection(int $id, ?string $module = null): array
    {
        $rows = [];
        foreach (FindingRepository::search(['domain_id' => $id, 'status' => 'active', 'module' => $module ?? '']) as $f) {
            $rows[] = [severity_label($f['severity']), $f['title'], $f['category'], $f['subject'], $f['reasoning'], $f['recommendation'], $f['last_seen']];
        }
        return ['title' => 'Offene Findings', 'columns' => ['Schweregrad', 'Titel', 'Kategorie', 'Betroffen', 'Begründung', 'Empfehlung', 'Zuletzt gesehen'], 'rows' => $rows];
    }
}

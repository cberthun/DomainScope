<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\{DnsLookup, RecordFormatter};
use DomainScope\Services\TLS\SmtpTlsInspector;

/** Härtung: CAA-Analyse, DANE/TLSA und (optional, ausdrücklich ausgelöst) STARTTLS-Test der MX-Server. */
final class HardeningService
{
    /** Zuordnung gängiger Zertifikatsaussteller (Teilstring des Issuer-CN/O) zu CAA-Bezeichnern. */
    public const CA_MAP = [
        "let's encrypt" => ['letsencrypt.org'], 'isrg' => ['letsencrypt.org'], 'digicert' => ['digicert.com'], 'geotrust' => ['digicert.com'],
        'rapidssl' => ['digicert.com'], 'thawte' => ['digicert.com'], 'sectigo' => ['sectigo.com', 'comodoca.com'], 'comodo' => ['comodoca.com', 'sectigo.com'],
        'usertrust' => ['sectigo.com', 'comodoca.com'], 'zerossl' => ['sectigo.com'], 'globalsign' => ['globalsign.com'], 'amazon' => ['amazon.com', 'amazontrust.com', 'awstrust.com'],
        'google trust' => ['pki.goog'], 'godaddy' => ['godaddy.com'], 'starfield' => ['godaddy.com'], 'buypass' => ['buypass.com'],
        'telekom' => ['telesec.de'], 'telesec' => ['telesec.de'], 'harica' => ['harica.gr'], 'ssl.com' => ['ssl.com'], 'entrust' => ['entrust.net'],
    ];

    public function __construct(private readonly DnsLookup $dns, private readonly SmtpTlsInspector $smtp = new SmtpTlsInspector())
    {
    }

    /**
     * @param string[] $mxHosts
     * @param string[] $observedIssuers Aussteller-CNs der tatsächlich ausgelieferten Zertifikate
     * @return array<string,mixed>
     */
    public function run(string $domain, array $mxHosts, array $observedIssuers, ?string $dnssecState, bool $starttls): array
    {
        return [
            'domain' => $domain, 'checked_at' => gmdate('Y-m-d H:i:s'),
            'caa' => $this->caa($domain, $observedIssuers),
            'tlsa' => $this->tlsa($domain, $mxHosts, $dnssecState),
            'starttls' => $starttls ? $this->starttls($mxHosts) : null,
            'starttls_requested' => $starttls,
        ];
    }

    /** @return array<string,mixed> */
    public function caa(string $domain, array $observedIssuers): array
    {
        $r = $this->dns->values($domain, 'CAA');
        $out = ['status' => $r['status'], 'records' => [], 'issue' => [], 'issuewild' => [], 'iodef' => [], 'findings' => [], 'allows_none' => false, 'error' => $r['error']];
        if (in_array($r['status'], ['timeout', 'error', 'servfail'], true)) {
            $out['findings'][] = ['code' => 'caa.unknown', 'level' => 'unknown', 'message' => 'CAA konnte nicht abgefragt werden (' . ($r['error'] ?? $r['status']) . ').'];
            return $out;
        }
        foreach ($r['values'] as $v) {
            $p = RecordFormatter::parseCaa($v);
            if ($p === null) {
                continue;
            }
            $out['records'][] = $p + ['raw' => $v];
            $val = strtolower(trim(explode(';', $p['value'])[0]));
            match ($p['tag']) {
                'issue' => $out['issue'][] = $val,
                'issuewild' => $out['issuewild'][] = $val,
                'iodef' => $out['iodef'][] = $p['value'],
                default => null,
            };
        }
        $f = &$out['findings'];
        if ($out['records'] === []) {
            $f[] = ['code' => 'caa.missing', 'level' => 'info', 'message' => 'Kein CAA-Record: Jede Zertifizierungsstelle darf Zertifikate für die Domain ausstellen.',
                'recommendation' => 'CAA-Records setzen, z. B. 0 issue "letsencrypt.org" (nur genutzte CAs erlauben) und 0 iodef "mailto:security@' . $domain . '".'];
            return $out;
        }
        $allowed = array_values(array_filter($out['issue'], static fn($v) => $v !== ''));
        $out['allows_none'] = $out['issue'] !== [] && $allowed === [];
        if ($out['issue'] === []) {
            $f[] = ['code' => 'caa.no_issue', 'level' => 'low', 'message' => 'CAA enthält keinen issue-Eintrag: Für normale Zertifikate gilt damit keine Einschränkung.',
                'recommendation' => 'Mindestens einen issue-Eintrag für die genutzte CA setzen.'];
        }
        if (count(array_unique($allowed)) > 3) {
            $f[] = ['code' => 'caa.broad', 'level' => 'low', 'message' => 'CAA erlaubt ' . count(array_unique($allowed)) . ' verschiedene Zertifizierungsstellen – die Einschränkung ist schwach.',
                'recommendation' => 'Nur tatsächlich genutzte CAs zulassen.'];
        }
        if ($out['issuewild'] === [] && $allowed !== []) {
            $f[] = ['code' => 'caa.no_issuewild', 'level' => 'info', 'message' => 'Kein issuewild-Eintrag: Wildcard-Zertifikate folgen den issue-Einträgen.', 'recommendation' => 'Falls keine Wildcards genutzt werden: 0 issuewild ";" setzen.'];
        }
        if ($out['iodef'] === []) {
            $f[] = ['code' => 'caa.no_iodef', 'level' => 'info', 'message' => 'Kein iodef-Eintrag: CAs können Verstöße nicht an eine Kontaktadresse melden.', 'recommendation' => '0 iodef "mailto:…" ergänzen.'];
        }
        // Passt die tatsächlich genutzte CA zu CAA?
        if ($allowed !== [] || $out['allows_none']) {
            foreach (array_unique($observedIssuers) as $issuer) {
                $caIds = null;
                foreach (self::CA_MAP as $needle => $ids) {
                    if (str_contains(strtolower($issuer), $needle)) {
                        $caIds = $ids;
                        break;
                    }
                }
                if ($caIds === null) {
                    continue;
                }
                if ($out['allows_none'] || array_intersect($caIds, $allowed) === []) {
                    $f[] = ['code' => 'caa.issuer_mismatch', 'level' => 'warn', 'subject' => $issuer,
                        'message' => "Das ausgelieferte Zertifikat stammt von „" . (preg_match('/CN=([^,]+)/', $issuer, $cnm) ? $cnm[1] : $issuer) . "“ ({$caIds[0]}), CAA erlaubt aber: " . ($allowed ? implode(', ', $allowed) : 'keine CA') . '. Eine Verlängerung bei dieser CA würde scheitern.',
                        'recommendation' => 'CAA um die genutzte CA ergänzen oder zu einer erlaubten CA wechseln.'];
                }
            }
        }
        return $out;
    }

    /**
     * @param string[] $mxHosts
     * @return array<string,mixed>
     */
    public function tlsa(string $domain, array $mxHosts, ?string $dnssecState): array
    {
        $names = [];
        foreach (array_slice($mxHosts, 0, 5) as $h) {
            $names["_25._tcp.$h"] = ['type' => 'SMTP', 'host' => $h];
        }
        $names["_443._tcp.$domain"] = ['type' => 'HTTPS', 'host' => $domain];
        $res = ['records' => [], 'findings' => [], 'checked' => array_keys($names)];
        foreach ($names as $name => $meta) {
            $r = $this->dns->values($name, 'TLSA');
            foreach ($r['values'] as $v) {
                $res['records'][] = ['name' => $name, 'service' => $meta['type'], 'data' => $v];
            }
        }
        if ($res['records'] === []) {
            $res['findings'][] = ['code' => 'dane.none', 'level' => 'info', 'message' => 'Keine TLSA-Records (DANE) gefunden – optional; DANE setzt DNSSEC voraus.'];
            return $res;
        }
        if ($dnssecState !== 'signed') {
            $res['findings'][] = ['code' => 'dane.no_dnssec', 'level' => 'warn',
                'message' => 'TLSA-Records existieren, die Zone ist aber nicht (nachweislich konsistent) DNSSEC-signiert. Ohne DNSSEC ignorieren Clients DANE bzw. werten es als unsicher.',
                'recommendation' => 'DNSSEC aktivieren und DS beim Registrar hinterlegen – oder TLSA entfernen.'];
        } else {
            $res['findings'][] = ['code' => 'dane.present', 'level' => 'pass', 'message' => count($res['records']) . ' TLSA-Record(s) bei signierter Zone gefunden.'];
        }
        foreach ($res['records'] as $rec) {
            if (!preg_match('/^(\d)\s+(\d)\s+(\d)\s+[0-9a-fA-F]+$/', trim($rec['data']), $m)) {
                $res['findings'][] = ['code' => 'dane.bad_record', 'level' => 'warn', 'message' => "TLSA-Record {$rec['name']} hat ein ungültiges Format.", 'subject' => $rec['name']];
            } elseif ((int) $m[1] < 2 && $rec['service'] === 'SMTP') {
                $res['findings'][] = ['code' => 'dane.usage', 'level' => 'info', 'subject' => $rec['name'],
                    'message' => "TLSA {$rec['name']} nutzt Usage {$m[1]} (PKIX). Für SMTP-DANE werden Usage 2 (DANE-TA) oder 3 (DANE-EE) empfohlen (RFC 7672)."];
            }
        }
        return $res;
    }

    /**
     * @param string[] $mxHosts
     * @return array<string,mixed>
     */
    public function starttls(array $mxHosts): array
    {
        $out = ['hosts' => [], 'findings' => []];
        foreach (array_slice($mxHosts, 0, 5) as $h) {
            $r = $this->smtp->inspect($h);
            $out['hosts'][] = $r;
            $subject = $h;
            switch ($r['status']) {
                case 'unreachable':
                    $out['findings'][] = ['code' => 'starttls.unreachable', 'level' => 'unknown', 'subject' => $subject,
                        'message' => "Port 25 von $h war von diesem Server aus nicht erreichbar: " . ($r['error'] ?? '?') . ' Das ist kein Befund über den Mailserver.'];
                    break;
                case 'no_starttls':
                    $out['findings'][] = ['code' => 'starttls.missing', 'level' => 'fail', 'subject' => $subject,
                        'message' => "$h bietet kein STARTTLS an – eingehende Mails werden unverschlüsselt übertragen.",
                        'recommendation' => 'TLS im Mailserver aktivieren (Postfix: smtpd_tls_security_level=may oder höher).'];
                    break;
                case 'tls_failed':
                    $out['findings'][] = ['code' => 'starttls.failed', 'level' => 'warn', 'subject' => $subject, 'message' => "$h: TLS nach STARTTLS fehlgeschlagen: " . ($r['error'] ?? '?')];
                    break;
                default:
                    if ($r['expired']) {
                        $out['findings'][] = ['code' => 'starttls.expired', 'level' => 'fail', 'subject' => $subject, 'message' => "Das SMTP-Zertifikat von $h ist abgelaufen.", 'recommendation' => 'Zertifikat des Mailservers erneuern.'];
                    } elseif ($r['days_left'] !== null && $r['days_left'] <= 14) {
                        $out['findings'][] = ['code' => 'starttls.expiring', 'level' => 'warn', 'subject' => $subject, 'message' => "Das SMTP-Zertifikat von $h läuft in {$r['days_left']} Tagen ab."];
                    }
                    if ($r['hostname_match'] === false) {
                        $out['findings'][] = ['code' => 'starttls.hostname', 'level' => 'warn', 'subject' => $subject, 'message' => "Das SMTP-Zertifikat von $h enthält den MX-Namen nicht (relevant für MTA-STS enforce und DANE).", 'recommendation' => 'Zertifikat mit dem MX-Hostnamen im SAN ausstellen.'];
                    }
                    if ($r['chain_trusted'] === false && !$r['expired']) {
                        $out['findings'][] = ['code' => 'starttls.untrusted', 'level' => 'warn', 'subject' => $subject, 'message' => "Zertifikat von $h nicht vertrauenswürdig: {$r['trust_error']} (opportunistisches TLS toleriert das, MTA-STS enforce nicht).", 'recommendation' => 'Zertifikat einer öffentlichen CA mit vollständiger Kette verwenden.'];
                    }
                    if (in_array($r['protocol'], ['TLSv1', 'TLSv1.0', 'TLSv1.1'], true)) {
                        $out['findings'][] = ['code' => 'starttls.legacy', 'level' => 'warn', 'subject' => $subject, 'message' => "$h verhandelt veraltetes {$r['protocol']}.", 'recommendation' => 'Auf TLS 1.2/1.3 beschränken.'];
                    }
            }
        }
        return $out;
    }
}

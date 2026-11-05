<?php
declare(strict_types=1);

namespace DomainScope\Findings;

use DomainScope\Support\Settings;

/**
 * Regelbasierte Findings-Engine. Jede Regel leitet aus tatsächlichen Prüfresultaten einen Entwurf ab.
 * Grundsätze:
 *  - Fehlende Informationen (nicht erreichbare Quellen, nicht konfigurierte optionale Features) sind keine
 *    Sicherheitslücken: sie erhalten "Information" oder "Unbekannt", nie automatisch eine hohe Stufe.
 *  - Der Schweregrad folgt der dokumentierten Regel (siehe RULES) und wird nicht aus einem Gesamtscore gemittelt.
 */
final class FindingsEngine
{
    /** Dokumentation der Regeln (Anzeige auf der Findings-Seite). */
    public const RULES = [
        // E-Mail
        'spf.multiple' => ['email', 'high', 'Mehrere SPF-Records → PermError (RFC 7208 §4.5).'],
        'spf.lookup_limit' => ['email', 'high', 'Mehr als 10 DNS-auslösende Mechanismen → PermError.'],
        'spf.lookup_near_limit' => ['email', 'low', '9–10 Lookups: kaum Reserve.'],
        'spf.plus_all' => ['email', 'critical', '"+all" erlaubt jedem Server das Senden.'],
        'spf.neutral_all' => ['email', 'medium', '"?all" trifft keine Aussage.'],
        'spf.no_all' => ['email', 'medium', 'Kein abschließendes all/redirect.'],
        'spf.missing' => ['email', 'medium/low', 'Kein SPF; mittel nur wenn Domain Mails empfängt (MX), sonst niedrig.'],
        'dmarc.missing' => ['email', 'medium/low', 'Kein DMARC; mittel nur wenn Domain Mails empfängt, sonst niedrig.'],
        'dmarc.p_none' => ['email', 'medium', 'p=none erzwingt nichts.'],
        'mtasts.mx_mismatch' => ['email', 'high/medium', 'MTA-STS-Policy deckt MX nicht ab (enforce: hoch, testing: mittel).'],
        // TLS
        'tls.expired' => ['tls', 'critical', 'Zertifikat abgelaufen.'],
        'tls.expiring' => ['tls', 'low–high', 'Schwellwerte aus den Einstellungen (Standard 30/14/7 Tage).'],
        'tls.hostname_mismatch' => ['tls', 'high', 'Hostname steht nicht in CN/SAN.'],
        'tls.untrusted' => ['tls', 'high', 'Kette führt nicht zu einer vertrauenswürdigen CA.'],
        'tls.unreachable' => ['tls', 'unknown', 'Host löst auf, TLS-Verbindung kam nicht zustande – kein Zertifikatsbefund.'],
        // DNSSEC
        'dnssec.validation_failure' => ['dnssec', 'critical', 'Validierende Resolver liefern SERVFAIL, mit CD aber Antwort.'],
        'dnssec.ds_without_dnskey' => ['dnssec', 'critical', 'DS im Parent, aber keine DNSKEYs.'],
        'dnssec.ds_mismatch' => ['dnssec', 'high', 'Kein DS passt zu einem DNSKEY.'],
        // Registrierung
        'rdap.expired' => ['registration', 'critical', 'Registrierung abgelaufen.'],
        'rdap.expiring' => ['registration', 'low–high', 'Schwellwerte aus den Einstellungen (Standard 60/30/14 Tage).'],
        'rdap.hold_status' => ['registration', 'high', 'clientHold/serverHold: Domain wird nicht aufgelöst.'],
        // DNS
        'dns.inconsistent' => ['dns', 'medium/low', 'Resolver liefern unterschiedliche Records (NS/MX/TXT: mittel, A/AAAA: niedrig).'],
    ];

    /** @return array<string,mixed> */
    private static function d(string $rule, string $title, string $cat, string $sev, string $why, string $fix, string $subject, array $evidence, string $source): array
    {
        return ['rule_id' => $rule, 'title' => $title, 'category' => $cat, 'severity' => $sev, 'reasoning' => $why, 'recommendation' => $fix,
            'subject' => $subject, 'evidence' => $evidence, 'source' => $source];
    }

    // ------------------------------------------------------------------ E-Mail

    /** @param array<string,mixed> $report EmailSecurityService::run() */
    public static function forEmail(string $domain, array $report): array
    {
        $out = [];
        $mail = (bool) ($report['receives_mail'] ?? false);
        $map = [
            'spf.multiple' => 'high', 'spf.lookup_limit' => 'high', 'spf.syntax' => 'high', 'spf.loop' => 'high',
            'spf.include_missing' => 'high', 'spf.include_no_record' => 'high', 'spf.void_limit' => 'medium', 'spf.mx_limit' => 'medium',
            'spf.plus_all' => 'critical', 'spf.neutral_all' => 'medium', 'spf.no_all' => 'medium',
            'spf.missing' => $mail ? 'medium' : 'low', 'spf.lookup_near_limit' => 'low', 'spf.ptr' => 'low', 'spf.long_record' => 'low',
            'spf.wide_range' => 'info', 'spf.include_unreachable' => 'unknown', 'spf.void_a' => 'low', 'spf.void_mx' => 'low',
            'dmarc.missing' => $mail ? 'medium' : 'low', 'dmarc.p_none' => 'medium', 'dmarc.pct' => 'low', 'dmarc.multiple' => 'high',
            'dmarc.no_p' => 'high', 'dmarc.bad_p' => 'high', 'dmarc.bad_sp' => 'medium', 'dmarc.sp_weaker' => 'low',
            'dmarc.external_unauthorized' => 'low', 'dmarc.no_rua' => 'info', 'dmarc.syntax_v' => 'low', 'dmarc.bad_pct' => 'medium',
            'dmarc.bad_adkim' => 'low', 'dmarc.bad_aspf' => 'low', 'dmarc.bad_uri' => 'low', 'dmarc.no_spf' => 'info',
            'dkim.weak_key' => 'high', 'dkim.short_key' => 'medium', 'dkim.bad_key' => 'medium', 'dkim.testing' => 'low',
            'dkim.revoked' => 'info', 'dkim.no_p' => 'medium', 'dkim.bad_version' => 'medium', 'dkim.bad_keytype' => 'medium',
            'dkim.sha1_only' => 'low', 'dkim.service_type' => 'low',
            'mtasts.mx_mismatch' => null, 'mtasts.policy_unreachable' => 'medium', 'mtasts.policy_http' => 'medium',
            'mtasts.policy_syntax' => 'medium', 'mtasts.testing' => 'low', 'mtasts.missing' => 'info', 'mtasts.max_age_short' => 'low',
            'mtasts.bad_id' => 'medium', 'mtasts.multiple' => 'medium', 'mtasts.content_type' => 'low',
            'tlsrpt.missing' => 'info', 'tlsrpt.no_rua' => 'low', 'tlsrpt.bad_uri' => 'low', 'tlsrpt.multiple' => 'low',
            'mx.cname' => 'medium', 'mx.unresolvable' => 'high', 'mx.private_ip' => 'high', 'mx.ptr_missing' => 'low',
            'mx.ptr_mismatch' => 'low', 'mx.single' => 'info', 'mx.missing' => $mail ? 'low' : 'info',
            'bimi.dmarc_required' => 'low', 'bimi.logo_https' => 'low', 'bimi.logo_unreachable' => 'low', 'bimi.logo_type' => 'low',
            'bimi.logo_not_svg' => 'low', 'bimi.logo_profile' => 'info', 'bimi.logo_size' => 'low', 'bimi.vmc_https' => 'low',
        ];
        $skip = ['spf.softfail_all', 'spf.hardfail_all', 'spf.truncated', 'spf.redirect_ignored', 'dkim.none_found', 'dkim.no_selectors',
            'dkim.strict_subdomain', 'dmarc.inherited', 'dmarc.ruf', 'dmarc.p_quarantine', 'dmarc.p_reject', 'bimi.no_vmc', 'bimi.no_logo',
            'mx.null', 'mtasts.enforce', 'mtasts.none'];
        $categories = ['spf' => 'E-Mail: SPF', 'dkim' => 'E-Mail: DKIM', 'dmarc' => 'E-Mail: DMARC', 'mtasts' => 'E-Mail: MTA-STS',
            'tlsrpt' => 'E-Mail: TLS-RPT', 'mx' => 'E-Mail: MX/PTR', 'bimi' => 'E-Mail: BIMI'];
        foreach (($report['checks'] ?? []) as $check) {
            foreach ($check['findings'] as $f) {
                $code = $f['code'];
                if (in_array($code, $skip, true) || $f['level'] === 'pass') {
                    continue;
                }
                $sev = $map[$code] ?? match ($f['level']) { 'fail' => 'medium', 'warn' => 'low', default => 'info' };
                if ($code === 'mtasts.mx_mismatch') {
                    $sev = $f['level'] === 'fail' ? 'high' : 'medium';
                }
                $prefix = explode('.', $code)[0];
                $subject = in_array($prefix, ['dkim', 'mx'], true) ? self::subjectFromMessage($f['message']) : '';
                $out[] = self::d(
                    $code, self::titleFor($code, $f['message']), $categories[$prefix] ?? 'E-Mail',
                    $sev, $f['message'] . (!empty($f['impact']) ? ' ' . $f['impact'] : ''),
                    (string) ($f['recommendation'] ?: 'Konfiguration prüfen.'),
                    $subject, ['record' => $check['record'] ?? null, 'kind' => $f['kind']], 'E-Mail-Sicherheitsprüfung (DNS/HTTPS)'
                );
            }
        }
        return self::unique($out);
    }

    private static function subjectFromMessage(string $m): string
    {
        if (preg_match('/^\[([^\]]+)\]/', $m, $x)) {
            return $x[1];
        }
        if (preg_match('/\b([a-z0-9._-]+\.[a-z]{2,})\b/i', $m, $x)) {
            return strtolower($x[1]);
        }
        return '';
    }

    private static function titleFor(string $code, string $message): string
    {
        return match ($code) {
            'spf.multiple' => 'Mehrere SPF-Records vorhanden',
            'spf.lookup_limit' => 'SPF-Lookup-Limit überschritten',
            'spf.lookup_near_limit' => 'SPF-Lookup-Limit fast erreicht',
            'spf.plus_all' => 'SPF erlaubt jeden Absender (+all)',
            'spf.neutral_all' => 'SPF endet mit ?all (neutral)',
            'spf.no_all' => 'SPF ohne abschließende Policy',
            'spf.missing' => 'Kein SPF-Record',
            'spf.syntax' => 'Syntaxfehler im SPF-Record',
            'spf.loop' => 'Zyklische SPF-Abhängigkeit',
            'spf.include_missing', 'spf.include_no_record' => 'SPF-Include nicht auflösbar',
            'spf.include_unreachable' => 'SPF-Include nicht abfragbar',
            'spf.void_limit' => 'SPF-Void-Lookup-Limit überschritten',
            'dmarc.missing' => 'Kein DMARC-Record',
            'dmarc.p_none' => 'DMARC-Policy ist p=none',
            'dmarc.pct' => 'DMARC gilt nur für einen Teil der Mails (pct<100)',
            'dmarc.multiple' => 'Mehrere DMARC-Records vorhanden',
            'dmarc.no_rua' => 'DMARC ohne Aggregate-Report-Adresse',
            'dmarc.sp_weaker' => 'DMARC-Subdomain-Policy schwächer als Domain-Policy',
            'dkim.weak_key' => 'DKIM-Schlüssel zu schwach (<1024 Bit)',
            'dkim.short_key' => 'DKIM-Schlüssel unter 2048 Bit',
            'dkim.testing' => 'DKIM im Testmodus (t=y)',
            'dkim.revoked' => 'DKIM-Schlüssel widerrufen',
            'mtasts.missing' => 'MTA-STS nicht konfiguriert',
            'mtasts.testing' => 'MTA-STS nur im Testmodus',
            'mtasts.mx_mismatch' => 'MTA-STS-Policy passt nicht zu den MX-Hosts',
            'mtasts.policy_unreachable' => 'MTA-STS-Policy nicht abrufbar',
            'tlsrpt.missing' => 'TLS-RPT nicht konfiguriert',
            'mx.cname' => 'MX zeigt auf einen CNAME',
            'mx.unresolvable' => 'MX-Host nicht auflösbar',
            'mx.ptr_missing' => 'Kein PTR-Record für Mailserver-IP',
            'mx.ptr_mismatch' => 'PTR-Record des Mailservers inkonsistent',
            default => mb_strimwidth(preg_replace('/^\[[^\]]+\]\s*/', '', $message) ?? $message, 0, 110, '…'),
        };
    }

    // --------------------------------------------------------------------- TLS

    /** @param array<int,array<string,mixed>> $checks Ergebnisse von TlsInspector::inspect() */
    public static function forTls(string $domain, array $checks): array
    {
        $out = [];
        $thresholds = Settings::days('cert_warn_days') ?: [30, 14, 7];
        foreach ($checks as $c) {
            $subject = $c['host'] . ':' . $c['port'];
            $src = 'TLS-Prüfung (PHP/OpenSSL)';
            if ($c['status'] === 'unreachable') {
                if (in_array($c['error_stage'] ?? '', ['connect', 'handshake'], true)) {
                    $out[] = self::d('tls.unreachable', "TLS-Verbindung zu $subject nicht möglich", 'TLS', 'unknown',
                        "Der Host löst auf {$c['ip']} auf, aber die TLS-Verbindung kam nicht zustande: {$c['error']} Das ist kein Zertifikatsbefund; der Dienst ist unter diesem Port eventuell nicht vorgesehen.",
                        'Prüfen, ob der Dienst läuft und Port erreichbar ist; falls nicht vorgesehen, Finding ignorieren.', $subject, ['error' => $c['error'], 'stage' => $c['error_stage']], $src);
                }
                continue;
            }
            $cert = $c['certificate'] ?? null;
            if ($cert === null) {
                continue;
            }
            $ev = ['host' => $c['host'], 'ip' => $c['ip'], 'not_after' => $cert['not_after'], 'issuer' => $cert['issuer'], 'fingerprint' => $cert['fingerprint_sha256']];
            if ($c['expired']) {
                $out[] = self::d('tls.expired', "Zertifikat für $subject ist abgelaufen", 'TLS', 'critical',
                    "Das Zertifikat ist seit {$cert['not_after']} UTC abgelaufen. Browser und Clients verweigern die Verbindung oder zeigen Warnungen.",
                    'Zertifikat umgehend erneuern (ACME/Let’s Encrypt oder CA) und Automatisierung prüfen.', $subject, $ev, $src);
            } elseif ($c['days_left'] !== null) {
                $sev = self::expirySeverity((int) $c['days_left'], $thresholds);
                if ($sev !== null) {
                    $out[] = self::d('tls.expiring', "Zertifikat für $subject läuft in {$c['days_left']} Tagen ab", 'TLS', $sev,
                        "Ablaufdatum {$cert['not_after']} UTC; Warnschwelle ≤ " . implode('/', $thresholds) . ' Tage (Einstellungen).',
                        'Zertifikat erneuern bzw. die automatische Verlängerung (ACME-Client, Cron) prüfen.', $subject, $ev + ['days_left' => $c['days_left']], $src);
                }
            }
            if ($c['hostname_match'] === false) {
                $out[] = self::d('tls.hostname_mismatch', "Zertifikat für $subject passt nicht zum Hostnamen", 'TLS', 'high',
                    "Der Hostname {$c['host']} steht weder in den SANs (" . implode(', ', array_slice($cert['sans'], 0, 6)) . ') noch (bei fehlenden SANs) im CN.',
                    'Zertifikat mit passendem SAN ausstellen oder den korrekten vHost/SNI-Eintrag konfigurieren.', $subject, $ev + ['sans' => $cert['sans']], $src);
            }
            if ($c['chain_trusted'] === false && !$c['expired']) {
                $out[] = self::d('tls.untrusted', "Zertifikatskette für $subject nicht vertrauenswürdig", 'TLS', 'high',
                    (string) $c['trust_error'], 'Vollständige Kette (inkl. Intermediate) ausliefern bzw. Zertifikat einer öffentlichen CA verwenden.', $subject, $ev + ['trust_error' => $c['trust_error']], $src);
            }
            if (in_array($c['protocol'], ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3'], true)) {
                $out[] = self::d('tls.legacy_protocol', "$subject verhandelt veraltetes Protokoll {$c['protocol']}", 'TLS', 'medium',
                    'Es wurde nur ein veraltetes Protokoll ausgehandelt, obwohl der Client TLS 1.3 anbietet.', 'Server auf TLS 1.2/1.3 beschränken.', $subject, $ev + ['protocol' => $c['protocol']], $src);
            }
            if ($cert['key_type'] === 'RSA' && $cert['key_bits'] !== null && $cert['key_bits'] < 2048) {
                $out[] = self::d('tls.weak_key', "Zertifikat von $subject nutzt schwachen RSA-Schlüssel ({$cert['key_bits']} Bit)", 'TLS', 'medium',
                    'RSA-Schlüssel unter 2048 Bit gelten nicht mehr als sicher.', 'Neues Zertifikat mit ≥ 2048 Bit RSA oder ECDSA P-256 erstellen.', $subject, $ev, $src);
            }
            if (preg_match('/sha1|md5/i', (string) $cert['signature_algorithm'])) {
                $out[] = self::d('tls.weak_signature', "Zertifikat von $subject mit schwacher Signatur ({$cert['signature_algorithm']})", 'TLS', 'high',
                    'SHA-1/MD5-Signaturen werden von Clients nicht mehr akzeptiert.', 'Zertifikat mit SHA-256 oder stärker neu ausstellen.', $subject, $ev, $src);
            }
        }
        return $out;
    }

    /** @param int[] $thresholds absteigend */
    public static function expirySeverity(int $daysLeft, array $thresholds): ?string
    {
        rsort($thresholds);
        $n = count($thresholds);
        $hit = null;
        foreach ($thresholds as $i => $t) {
            if ($daysLeft <= $t) {
                $hit = $i;
            }
        }
        if ($hit === null) {
            return null;
        }
        // Engster Schwellwert = hoch, mittlerer = mittel, weitester = niedrig
        if ($n === 1) {
            return 'medium';
        }
        $pos = $hit / ($n - 1);
        return $pos >= 1 ? 'high' : ($pos > 0 ? 'medium' : 'low');
    }

    // ------------------------------------------------------------------ DNSSEC

    /** @param array<string,mixed> $a DnssecService::analyze() */
    public static function forDnssec(string $domain, array $a): array
    {
        $sev = [
            'dnssec.validation_failure' => 'critical', 'dnssec.ds_without_dnskey' => 'critical', 'dnssec.ds_mismatch' => 'high',
            'dnssec.rrsig_expired' => 'high', 'dnssec.rrsig_invalid' => 'high', 'dnssec.no_ds' => 'medium',
            'dnssec.algorithm_insecure' => 'medium', 'dnssec.algorithm_deprecated' => 'low', 'dnssec.rrsig_expiring' => 'medium',
            'dnssec.rrsig_not_yet_valid' => 'low', 'dnssec.ds_extra' => 'low', 'dnssec.ds_sha1' => 'info', 'dnssec.nsec3_iterations' => 'info',
            'dnssec.no_ad' => 'unknown', 'dnssec.no_rrsig' => 'unknown', 'dnssec.weak_ksk' => 'low',
            'delegation.lame' => 'high', 'delegation.ns_unreachable' => 'medium', 'delegation.ns_unresolvable' => 'medium',
            'delegation.ns_mismatch' => 'medium', 'delegation.serial_mismatch' => 'low', 'delegation.dnskey_mismatch' => 'low',
            'delegation.single_ns' => 'low',
        ];
        $titles = [
            'dnssec.validation_failure' => 'DNSSEC-Validierung schlägt fehl (Domain für validierende Resolver nicht erreichbar)',
            'dnssec.ds_without_dnskey' => 'DS-Record ohne passende DNSKEYs (gebrochene DNSSEC-Delegation)',
            'dnssec.ds_mismatch' => 'DS-Record passt zu keinem DNSKEY',
            'dnssec.no_ds' => 'DNSKEY vorhanden, aber kein DS im Parent',
            'dnssec.rrsig_expired' => 'DNSSEC-Signatur abgelaufen',
            'dnssec.rrsig_expiring' => 'DNSSEC-Signatur läuft bald ab',
            'dnssec.rrsig_invalid' => 'DNSSEC-Signatur kryptografisch ungültig',
            'delegation.lame' => 'Nameserver nicht autoritativ (mögliche Lame Delegation)',
            'delegation.ns_unreachable' => 'Nameserver antwortet nicht',
            'delegation.ns_mismatch' => 'NS-Records in Parent und Zone weichen ab',
            'delegation.serial_mismatch' => 'Nameserver mit unterschiedlichen SOA-Serials',
            'delegation.single_ns' => 'Nur ein Nameserver konfiguriert',
        ];
        $out = [];
        foreach ($a['findings'] as $f) {
            $code = $f['code'];
            if (!isset($sev[$code])) {
                continue;
            }
            $out[] = self::d(
                $code, $titles[$code] ?? mb_strimwidth($f['message'], 0, 110, '…'),
                str_starts_with($code, 'delegation') ? 'Delegation' : 'DNSSEC', $sev[$code],
                $f['message'], $f['recommendation'] ?: 'Konfiguration beim DNS-Anbieter bzw. Registrar prüfen.',
                $code === 'dnssec.rrsig_expired' || $code === 'dnssec.rrsig_expiring' ? '' : self::hostFromDelegation($f['message']),
                ['state' => $a['state'], 'validation' => $a['validation']['level']], 'DNSSEC-Analyse (DoH + autoritative Abfragen)'
            );
        }
        return self::unique($out);
    }

    private static function hostFromDelegation(string $m): string
    {
        return preg_match('/Nameserver ([a-z0-9.-]+)/i', $m, $x) ? strtolower($x[1]) : '';
    }

    // ------------------------------------------------------------- Registrierung

    /** @param array<string,mixed> $reg normalisierte RDAP/WHOIS-Daten */
    public static function forRegistration(string $domain, array $reg): array
    {
        if (!($reg['ok'] ?? true)) {
            return [];
        }
        $out = [];
        $src = strtoupper((string) ($reg['source'] ?? 'RDAP')) . '-Abfrage';
        if (!empty($reg['expires_at'])) {
            $days = days_until($reg['expires_at']);
            $thresholds = Settings::days('domain_warn_days') ?: [60, 30, 14];
            if ($days !== null && $days < 0) {
                $out[] = self::d('rdap.expired', 'Domainregistrierung ist abgelaufen', 'Registrierung', 'critical',
                    "Laut {$reg['source']} lief die Registrierung am {$reg['expires_at']} UTC ab. Die Domain kann gelöscht oder gesperrt werden.",
                    'Domain umgehend beim Registrar verlängern bzw. Redemption-Optionen prüfen.', '', ['expires_at' => $reg['expires_at']], $src);
            } elseif ($days !== null && ($sev = self::expirySeverity($days, $thresholds)) !== null) {
                $out[] = self::d('rdap.expiring', "Domainregistrierung läuft in $days Tagen ab", 'Registrierung', $sev,
                    "Ablaufdatum laut {$reg['source']}: {$reg['expires_at']} UTC. Warnschwellen: " . implode('/', $thresholds) . ' Tage.',
                    'Domain verlängern oder automatische Verlängerung beim Registrar aktivieren.', '', ['expires_at' => $reg['expires_at'], 'days_left' => $days], $src);
            }
        }
        foreach ($reg['statuses'] ?? [] as $s) {
            $norm = strtolower(str_replace([' ', '_', '-'], '', (string) $s));
            if (in_array($norm, ['clienthold', 'serverhold'], true)) {
                $out[] = self::d('rdap.hold_status', "Domainstatus $s", 'Registrierung', 'high',
                    'Der Status ' . $s . ' bewirkt, dass die Domain aus der Zone entfernt wird und nicht mehr auflöst.',
                    'Ursache beim Registrar klären (Zahlung, Whois-Verifizierung, Missbrauchsmeldung).', $s, ['statuses' => $reg['statuses']], $src);
            }
            if (in_array($norm, ['pendingdelete', 'redemptionperiod'], true)) {
                $out[] = self::d('rdap.hold_status', "Domainstatus $s", 'Registrierung', $norm === 'pendingdelete' ? 'critical' : 'high',
                    'Die Domain befindet sich in der Löschphase (' . $s . ').', 'Umgehend beim Registrar wiederherstellen/verlängern.', $s, ['statuses' => $reg['statuses']], $src);
            }
        }
        return $out;
    }

    // --------------------------------------------------------------------- DNS

    /** @param array<string,array> $diffs Typ => ['a'=>[], 'b'=>[], 'resolvers'=>[x,y]] */
    public static function forDnsConsistency(string $domain, array $diffs): array
    {
        $out = [];
        foreach ($diffs as $type => $d) {
            $sev = in_array($type, ['NS', 'MX', 'TXT', 'CAA', 'SOA', 'DS', 'DNSKEY', 'CNAME'], true) ? 'medium' : 'low';
            $out[] = self::d('dns.inconsistent', "Resolver liefern unterschiedliche $type-Records", 'DNS', $sev,
                "{$d['resolvers'][0]} und {$d['resolvers'][1]} liefern für $type unterschiedliche Daten. " . ($sev === 'low'
                    ? 'Bei A/AAAA ist das häufig Geo-/Load-Balancing-DNS und nicht zwingend ein Fehler.'
                    : 'Das deutet auf Propagationsverzögerung, inkonsistente autoritative Nameserver oder Caching hin.'),
                'Autoritative Nameserver direkt vergleichen (DNSSEC-/Delegation-Tab) und TTL/Propagation abwarten.', $type,
                ['only_' . $d['resolvers'][0] => $d['only_a'], 'only_' . $d['resolvers'][1] => $d['only_b']], 'DNS-Resolver-Vergleich (DoH)');
        }
        return $out;
    }

    // --------------------------------------------------------------- Subdomains

    /**
     * @param array<string,array> $resolved Host => ['status','ips','cname']
     */
    public static function forSubdomains(string $domain, array $resolved, array $takeover = []): array
    {
        $out = [];
        foreach ($resolved as $host => $r) {
            $t = $takeover[$host] ?? null;
            if ($t !== null && $t['status'] === 'vulnerable') {
                $out[] = self::d('subdomain.takeover', "Möglicher Subdomain-Takeover: $host", 'Subdomains', 'high',
                    "$host zeigt per CNAME auf {$t['cname']}" . ($t['provider'] ? " ({$t['provider']})" : '') . '. ' . $t['evidence'] . ' Das ist ein starkes Indiz, aber kein Ausnutzbarkeitsnachweis.',
                    'Den DNS-Eintrag entfernen oder die Ressource beim Anbieter wieder anlegen und der eigenen Domain zuordnen.', $host, $t, 'Takeover-Prüfung (DNS + HTTP)');
            } elseif ($t !== null && $t['status'] === 'dangling') {
                $out[] = self::d('subdomain.dangling_cname', "Subdomain $host: CNAME-Ziel existiert nicht", 'Subdomains', 'medium',
                    "$host verweist per CNAME auf {$t['cname']}. {$t['evidence']} Verwaiste CNAMEs können je nach Anbieter übernommen werden.",
                    'Prüfen, ob der Zieldienst noch existiert; ansonsten den DNS-Eintrag entfernen.', $host, $t, 'Takeover-Prüfung (DNS)');
            } elseif ($r['status'] === 'dangling_cname' && $t === null) {
                $out[] = self::d('subdomain.dangling_cname', "Subdomain $host: CNAME ohne Ziel-Adresse", 'Subdomains', 'low',
                    "$host verweist per CNAME auf {$r['cname']}, das keine A/AAAA-Records liefert. Es wurde (noch) kein Takeover-Test durchgeführt.",
                    'Prüfen, ob der Zieldienst noch existiert; ansonsten den DNS-Eintrag entfernen.', $host, $r, 'Subdomain-Auflösung (DoH)');
            }
        }
        return $out;
    }

    // ---------------------------------------------------------------------- CT

    /** @param array<int,array<string,mixed>> $rows CtRepository::recentNew() */
    public static function forCt(string $domain, array $rows): array
    {
        $out = [];
        foreach ($rows as $c) {
            $names = implode(', ', array_slice($c['names_list'], 0, 5)) . (count($c['names_list']) > 5 ? ' …' : '');
            $unknown = !(int) $c['known_issuer'];
            $out[] = self::d($unknown ? 'ct.unknown_issuer' : 'ct.new_certificate',
                ($unknown ? 'Neues Zertifikat einer bisher unbekannten CA: ' : 'Neues Zertifikat in CT-Logs: ') . $c['issuer'],
                'Certificate Transparency', $unknown ? 'medium' : 'info',
                "In den CT-Logs wurde ein neues Zertifikat (Seriennr. {$c['serial']}) für $names entdeckt, ausgestellt von {$c['issuer']}" .
                ($unknown ? ', einer CA, die für diese Domain bisher weder in CT noch bei Ihren eigenen TLS-Prüfungen aufgetaucht ist.' : ' – einer für diese Domain bekannten CA (z. B. normale Erneuerung).') .
                ' DomainScope kann nicht wissen, wer das Zertifikat beantragt hat; es ist ein Hinweis, kein Nachweis für Missbrauch.',
                'Prüfen, ob Sie (oder ein Dienstleister/ACME-Client) das Zertifikat beantragt haben. Wenn nicht: CAA-Records setzen, Zertifikat bei der CA widerrufen lassen und DNS-/Validierungszugänge prüfen. Danach das Finding als „behoben“ oder „ignoriert“ markieren.',
                $c['serial'], ['issuer' => $c['issuer'], 'names' => array_slice($c['names_list'], 0, 20), 'not_before' => $c['not_before'], 'not_after' => $c['not_after'], 'ct_id' => $c['ct_id'], 'first_seen' => $c['first_seen']],
                'Certificate Transparency (crt.sh)');
        }
        return $out;
    }

    // --------------------------------------------------------------- Härtung

    /** @param array<string,mixed> $h HardeningService::run() */
    public static function forHardening(string $domain, array $h): array
    {
        $sev = [
            'caa.missing' => 'info', 'caa.no_issue' => 'low', 'caa.broad' => 'low', 'caa.no_issuewild' => 'info', 'caa.no_iodef' => 'info',
            'caa.issuer_mismatch' => 'medium', 'caa.unknown' => 'unknown', 'dane.no_dnssec' => 'medium', 'dane.bad_record' => 'low', 'dane.usage' => 'info',
            'starttls.missing' => 'medium', 'starttls.failed' => 'low', 'starttls.expired' => 'medium', 'starttls.expiring' => 'low',
            'starttls.hostname' => 'low', 'starttls.untrusted' => 'low', 'starttls.legacy' => 'medium', 'starttls.unreachable' => 'unknown',
        ];
        $titles = [
            'caa.missing' => 'Kein CAA-Record', 'caa.no_issue' => 'CAA ohne issue-Eintrag', 'caa.broad' => 'CAA erlaubt viele Zertifizierungsstellen',
            'caa.issuer_mismatch' => 'Genutzte CA ist durch CAA nicht erlaubt', 'dane.no_dnssec' => 'DANE/TLSA ohne DNSSEC',
            'starttls.missing' => 'Mailserver ohne STARTTLS', 'starttls.expired' => 'SMTP-Zertifikat abgelaufen', 'starttls.legacy' => 'Mailserver mit veraltetem TLS',
            'starttls.unreachable' => 'Port 25 nicht erreichbar (STARTTLS-Test nicht möglich)', 'starttls.untrusted' => 'SMTP-Zertifikat nicht vertrauenswürdig',
            'starttls.hostname' => 'SMTP-Zertifikat passt nicht zum MX-Namen', 'caa.no_iodef' => 'CAA ohne iodef-Kontakt', 'caa.no_issuewild' => 'CAA ohne issuewild',
        ];
        $findings = array_merge($h['caa']['findings'] ?? [], $h['tlsa']['findings'] ?? [], $h['starttls']['findings'] ?? []);
        $out = [];
        foreach ($findings as $f) {
            if (!isset($sev[$f['code']])) {
                continue;
            }
            $cat = str_starts_with($f['code'], 'caa') ? 'Härtung: CAA' : (str_starts_with($f['code'], 'dane') ? 'Härtung: DANE' : 'Härtung: STARTTLS');
            $out[] = self::d($f['code'], ($titles[$f['code']] ?? mb_strimwidth($f['message'], 0, 100, '…')) . (isset($f['subject']) && str_starts_with($f['code'], 'starttls') ? ' (' . $f['subject'] . ')' : ''), $cat,
                $sev[$f['code']], $f['message'], $f['recommendation'] ?? 'Konfiguration prüfen.', $f['subject'] ?? '', [], 'Härtungsprüfung (DNS' . (str_starts_with($f['code'], 'starttls') ? ', SMTP Port 25' : '') . ')');
        }
        return self::unique($out);
    }

    // -------------------------------------------------------------------- HTTP

    /** @param array<string,mixed> $h HttpCheckService::check() */
    public static function forHttp(string $domain, array $h): array
    {
        $out = [];
        $host = $h['host'];
        $src = 'HTTP-Erreichbarkeitsprüfung';
        $https = $h['https'];
        $http = $h['http'];
        if (!$https['reachable'] && $http['reachable'] && $https['error_code'] !== 'blocked') {
            $out[] = self::d('http.no_https', "$host ist nur per HTTP erreichbar", 'HTTP', 'medium',
                'HTTPS-Verbindung scheiterte (' . ($https['error'] ?? 'unbekannt') . '), HTTP antwortet mit Status ' . $http['status'] . '. Übertragungen sind unverschlüsselt.',
                'TLS-Zertifikat einrichten und HTTPS aktivieren.', $host, ['https_error' => $https['error']], $src);
        } elseif (!$https['reachable'] && !$http['reachable']) {
            if (in_array($https['error_code'], ['timeout', 'connect'], true) || in_array($http['error_code'], ['timeout', 'connect'], true)) {
                $out[] = self::d('http.unreachable', "$host per HTTP/HTTPS nicht erreichbar", 'HTTP', 'unknown',
                    'Weder HTTP noch HTTPS haben geantwortet (' . ($https['error'] ?? '?') . '). Ob der Host dienstfrei ist oder ein Ausfall vorliegt, lässt sich so nicht entscheiden.',
                    'Bei erwarteter Webseite: Webserver, Firewall und DNS prüfen.', $host, ['https' => $https['error'], 'http' => $http['error']], $src);
            }
        }
        if ($https['reachable'] && $http['reachable'] && $h['http_redirects_to_https'] === false) {
            $out[] = self::d('http.no_redirect', "$host leitet HTTP nicht auf HTTPS um", 'HTTP', 'low',
                'Aufrufe über http:// werden ausgeliefert, ohne auf https:// weitergeleitet zu werden.', 'Permanente Weiterleitung (301/308) auf HTTPS einrichten.', $host, [], $src);
        }
        if ($https['reachable'] && $https['status'] < 500 && empty($h['hsts'])) {
            $out[] = self::d('http.no_hsts', "$host sendet keinen HSTS-Header", 'HTTP', 'info',
                'Ohne Strict-Transport-Security akzeptieren Browser auch künftig unverschlüsselte Erstverbindungen (Downgrade-Risiko). Optionale Best Practice.',
                'Header "Strict-Transport-Security: max-age=31536000; includeSubDomains" setzen, sobald alle Subdomains HTTPS unterstützen.', $host, [], $src);
        }
        return $out;
    }

    /** @param array<int,array<string,mixed>> $drafts */
    private static function unique(array $drafts): array
    {
        $seen = [];
        $out = [];
        foreach ($drafts as $d) {
            $k = $d['rule_id'] . '|' . $d['subject'];
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $out[] = $d;
            }
        }
        return $out;
    }
}

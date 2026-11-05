<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;
use DomainScope\Services\Http\SafeHttp;

/** BIMI: TXT default._bimi, Logo-Datei (SVG) und DMARC-Voraussetzung. */
final class BimiAnalyzer
{
    use CheckBuilder;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /** @return array<string,mixed> */
    public function analyze(string $domain, bool $dmarcEnforcing): array
    {
        $this->reset();
        $res = $this->dns->txtWithPrefix('default._bimi.' . $domain, 'v=BIMI1');
        if (in_array($res['status'], ['timeout', 'error', 'servfail'], true)) {
            return $this->build('bimi', 'BIMI', 'error', 'BIMI konnte nicht geprüft werden: ' . ($res['error'] ?? $res['status']), null);
        }
        $records = array_values(array_filter($res['values'], static fn($v) => preg_match('/^v=BIMI1\s*(;|$)/i', trim($v)) === 1));
        if ($records === []) {
            return $this->build('bimi', 'BIMI', 'none', 'BIMI ist nicht konfiguriert (rein optionales Marketing-Feature).', null);
        }
        $t = $this->tags($records[0]);
        $logo = $t['l'] ?? '';
        $vmc = $t['a'] ?? '';
        $details = [['label' => 'Logo (l)', 'value' => $logo ?: '–'], ['label' => 'Zertifikat (a)', 'value' => $vmc ?: '–']];

        if (!$dmarcEnforcing) {
            $this->add('warn', 'technical', 'bimi.dmarc_required', 'BIMI setzt eine durchgesetzte DMARC-Policy (p=quarantine oder reject, pct=100) voraus.', 'Mailanbieter zeigen das Logo nicht an.', 'DMARC auf quarantine/reject anheben.');
        }
        if ($logo === '') {
            $this->add('info', 'technical', 'bimi.no_logo', 'Kein Logo (l=) angegeben. Ein leeres l= ist nur zum Deklinieren von BIMI zulässig.', null, null);
        } elseif (!str_starts_with(strtolower($logo), 'https://')) {
            $this->add('fail', 'technical', 'bimi.logo_https', 'Die Logo-URL muss https verwenden.', 'Das Logo wird nicht geladen.', 'https-URL angeben.');
        } else {
            $http = SafeHttp::request($logo, ['max_bytes' => 65536, 'timeout' => 10, 'source' => 'bimi-logo', 'label' => 'BIMI-Logo']);
            if ($http['error_code'] !== null || $http['status'] !== 200) {
                $this->add('fail', 'technical', 'bimi.logo_unreachable', 'Das Logo ist nicht abrufbar: ' . ($http['error'] ?? 'HTTP ' . $http['status']), 'Das Logo kann nicht angezeigt werden.', 'URL und Zertifikat des Hosts prüfen.');
            } else {
                $ct = strtolower($http['headers']['content-type'] ?? '');
                if (!str_contains($ct, 'image/svg+xml')) {
                    $this->add('warn', 'technical', 'bimi.logo_type', 'Content-Type des Logos ist "' . ($ct ?: 'leer') . '" (erwartet: image/svg+xml).', null, 'Datei als SVG ausliefern (SVG Tiny PS).');
                }
                if (!str_contains($http['body'], '<svg')) {
                    $this->add('fail', 'technical', 'bimi.logo_not_svg', 'Die Datei enthält kein SVG-Element.', null, 'Gültige SVG-Tiny-PS-Datei bereitstellen.');
                } elseif (!preg_match('/baseProfile\s*=\s*["\']tiny-ps["\']/i', $http['body'])) {
                    $this->add('warn', 'bestpractice', 'bimi.logo_profile', 'Das SVG deklariert nicht baseProfile="tiny-ps" (SVG Tiny Portable/Secure).', 'Viele Mailanbieter lehnen andere Profile ab.', 'Logo im Profil SVG Tiny PS exportieren.');
                }
                if ($http['truncated']) {
                    $this->add('warn', 'technical', 'bimi.logo_size', 'Das Logo überschreitet 64 KB (empfohlen: ≤ 32 KB).', null, 'Datei verkleinern.');
                }
            }
        }
        if ($vmc !== '' && !str_starts_with(strtolower($vmc), 'https://')) {
            $this->add('fail', 'technical', 'bimi.vmc_https', 'Die Zertifikats-URL (a=) muss https verwenden.', null, 'https-URL angeben.');
        }
        if ($vmc === '') {
            $this->add('info', 'bestpractice', 'bimi.no_vmc', 'Kein VMC/CMC-Zertifikat (a=) hinterlegt. Gmail und Apple Mail verlangen ein solches Zertifikat für die Logo-Anzeige.', null, null);
        }
        $status = $this->statusFromFindings();
        return $this->build('bimi', 'BIMI', $status, $status === 'pass' ? 'BIMI ist korrekt konfiguriert.' : 'BIMI ist konfiguriert, hat aber Auffälligkeiten.', $records[0], $details);
    }
}

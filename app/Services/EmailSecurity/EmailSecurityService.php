<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;

/** Führt alle E-Mail-Sicherheitsprüfungen zusammen. */
final class EmailSecurityService
{
    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /**
     * @param string[] $selectors
     * @return array<string,mixed>
     */
    public function run(string $domain, array $selectors = [], bool $dkimAutoscan = false): array
    {
        $started = microtime(true);
        $mxCheck = (new MailServerAnalyzer($this->dns))->analyze($domain);
        $spf = (new SpfAnalyzer($this->dns))->analyze($domain);
        $dkim = (new DkimAnalyzer($this->dns))->analyze($domain, $selectors, $dkimAutoscan);
        $dmarc = (new DmarcAnalyzer($this->dns))->analyze($domain, $spf);
        $mxHosts = array_column($mxCheck['hosts'] ?? [], 'host');
        $mtaSts = (new MtaStsAnalyzer($this->dns))->analyze($domain, $mxHosts);
        $tlsRpt = (new TlsRptAnalyzer($this->dns))->analyze($domain, ($mtaSts['policy']['mode'] ?? null) === 'enforce');
        $bimi = (new BimiAnalyzer($this->dns))->analyze($domain, (bool) ($dmarc['enforcing'] ?? false));

        $checks = ['mx' => $mxCheck, 'spf' => $spf, 'dkim' => $dkim, 'dmarc' => $dmarc, 'mta-sts' => $mtaSts, 'tls-rpt' => $tlsRpt, 'bimi' => $bimi];
        $tally = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'none' => 0, 'error' => 0];
        foreach ($checks as $c) {
            $tally[$c['status']] = ($tally[$c['status']] ?? 0) + 1;
        }
        return [
            'domain' => $domain,
            'checks' => $checks,
            'tally' => $tally,
            'receives_mail' => !($mxCheck['null_mx'] ?? false) && (($mxCheck['hosts'] ?? []) !== [] || ($mxCheck['implicit_mx'] ?? false)),
            'has_mx' => ($mxCheck['hosts'] ?? []) !== [],
            'dns_queries' => $this->dns->queries(),
            'duration_ms' => (int) round((microtime(true) - $started) * 1000),
            'checked_at' => gmdate('Y-m-d H:i:s'),
            'limitations' => [
                'DKIM: Selektoren lassen sich nicht per DNS auflisten; nur angegebene' . ($dkimAutoscan ? ' bzw. gängige' : '') . ' Selektoren wurden geprüft.',
                'SPF/DMARC werden statisch ausgewertet; makrobasierte Mechanismen (exists, include mit %{…}) können nicht aufgelöst werden.',
                'Es wurde keine Zustellung getestet; die Prüfung bewertet ausschließlich veröffentlichte DNS-/HTTPS-Konfiguration.',
            ],
        ];
    }
}

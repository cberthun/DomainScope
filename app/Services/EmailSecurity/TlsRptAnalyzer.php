<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;

/** TLS-RPT (RFC 8460): TXT-Record unter _smtp._tls. */
final class TlsRptAnalyzer
{
    use CheckBuilder;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /** @return array<string,mixed> */
    public function analyze(string $domain, bool $mtaStsActive): array
    {
        $this->reset();
        $res = $this->dns->txtWithPrefix('_smtp._tls.' . $domain, 'v=TLSRPTv1');
        if (in_array($res['status'], ['timeout', 'error', 'servfail'], true)) {
            return $this->build('tls-rpt', 'TLS-RPT', 'error', 'TLS-RPT konnte nicht geprüft werden: ' . ($res['error'] ?? $res['status']), null);
        }
        $records = array_values(array_filter($res['values'], static fn($v) => preg_match('/^v=TLSRPTv1\s*(;|$)/i', trim($v)) === 1));
        if ($records === []) {
            $this->add('info', 'bestpractice', 'tlsrpt.missing', 'Kein TLS-RPT-Record (_smtp._tls) vorhanden.', 'Fehler bei der TLS-Aushandlung eingehender Mails werden nicht berichtet.' . ($mtaStsActive ? ' Besonders relevant, da MTA-STS aktiv ist.' : ''), 'TXT-Record "v=TLSRPTv1; rua=mailto:tlsrpt@' . $domain . '" anlegen.');
            return $this->build('tls-rpt', 'TLS-RPT', 'none', 'TLS-RPT ist nicht konfiguriert (optionale Best Practice).', null);
        }
        if (count($records) > 1) {
            $this->add('fail', 'technical', 'tlsrpt.multiple', 'Mehrere TLS-RPT-Records vorhanden.', 'Sender ignorieren TLS-RPT.', 'Nur einen Record behalten.');
        }
        $t = $this->tags($records[0]);
        $rua = array_values(array_filter(array_map('trim', explode(',', $t['rua'] ?? ''))));
        $details = [['label' => 'rua', 'value' => $rua ? implode(', ', $rua) : '–']];
        if ($rua === []) {
            $this->add('fail', 'technical', 'tlsrpt.no_rua', 'Das Pflicht-Tag rua= fehlt.', 'Es können keine Reports zugestellt werden.', 'rua=mailto:… oder rua=https://… ergänzen.');
        }
        foreach ($rua as $u) {
            if (!preg_match('#^(mailto:[^@\s]+@[^@\s]+|https://\S+)$#i', $u)) {
                $this->add('fail', 'technical', 'tlsrpt.bad_uri', "Ungültige Report-URI: $u (erlaubt: mailto: oder https:).", null, 'URI korrigieren.');
            }
        }
        $status = $this->statusFromFindings();
        return $this->build('tls-rpt', 'TLS-RPT', $status, $status === 'pass' ? 'TLS-RPT ist konfiguriert.' : 'TLS-RPT-Record ist fehlerhaft.', $records[0], $details, ['rua' => $rua]);
    }
}

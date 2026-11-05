<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;
use DomainScope\Services\DNS\RecordFormatter;
use DomainScope\Services\Http\SafeHttp;

/** MTA-STS (RFC 8461): DNS-Record + Policy-Datei über HTTPS. */
final class MtaStsAnalyzer
{
    use CheckBuilder;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /**
     * @param string[] $mxHosts tatsächliche MX-Hosts der Domain
     * @return array<string,mixed>
     */
    public function analyze(string $domain, array $mxHosts): array
    {
        $this->reset();
        $res = $this->dns->txtWithPrefix('_mta-sts.' . $domain, 'v=STSv1');
        if (in_array($res['status'], ['timeout', 'error', 'servfail'], true)) {
            return $this->build('mta-sts', 'MTA-STS', 'error', 'MTA-STS konnte nicht geprüft werden: ' . ($res['error'] ?? $res['status']), null);
        }
        $records = array_values(array_filter($res['values'], static fn($v) => preg_match('/^v=STSv1\s*(;|$)/i', trim($v)) === 1));
        if ($records === []) {
            $this->add('info', 'bestpractice', 'mtasts.missing', 'Kein MTA-STS-Record (_mta-sts) vorhanden.', 'Eingehende Mails können per SMTP-Downgrade-Angriff ohne TLS zugestellt werden.', 'MTA-STS zunächst im Modus "testing" einführen (TXT-Record + Policy-Datei unter https://mta-sts.' . $domain . '/.well-known/mta-sts.txt).');
            return $this->build('mta-sts', 'MTA-STS', 'none', 'MTA-STS ist nicht konfiguriert (optionale Best Practice).', null);
        }
        if (count($records) > 1) {
            $this->add('fail', 'technical', 'mtasts.multiple', 'Mehrere MTA-STS-TXT-Records vorhanden.', 'Sendende Server ignorieren die Policy.', 'Nur einen Record behalten.');
        }
        $t = $this->tags($records[0]);
        $id = $t['id'] ?? '';
        if ($id === '' || !preg_match('/^[A-Za-z0-9]{1,32}$/', $id)) {
            $this->add('fail', 'technical', 'mtasts.bad_id', 'Das Tag id= fehlt oder ist ungültig (1–32 alphanumerische Zeichen).', 'Sender erkennen Policy-Änderungen nicht.', 'id mit einem eindeutigen Wert (z. B. Zeitstempel) setzen.');
        }

        // Policy-Datei
        $url = 'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt';
        $http = SafeHttp::request($url, [
            'follow' => false, 'max_bytes' => 65536, 'timeout' => 10,
            'source' => 'mta-sts-policy', 'label' => 'MTA-STS-Policy (HTTPS)',
        ]);
        $policy = null;
        $details = [['label' => 'Policy-URL', 'value' => $url], ['label' => 'Policy-ID (DNS)', 'value' => $id ?: '–']];
        if ($http['error_code'] !== null) {
            $msg = match ($http['error_code']) {
                'tls' => 'Das HTTPS-Zertifikat von mta-sts.' . $domain . ' ist ungültig oder nicht vertrauenswürdig: ' . $http['error'],
                'blocked' => 'Die Policy-URL wurde aus Sicherheitsgründen nicht abgerufen: ' . $http['error'],
                'timeout' => 'Zeitüberschreitung beim Abruf der Policy-Datei.',
                default => 'Die Policy-Datei ist nicht abrufbar: ' . $http['error'],
            };
            $level = $http['error_code'] === 'timeout' ? 'warn' : 'fail';
            $this->add($level, 'technical', 'mtasts.policy_unreachable', $msg, 'Sendende Server können die Policy nicht laden und wenden MTA-STS nicht an (bzw. nutzen eine ältere gecachte Policy).', 'Webserver mit gültigem Zertifikat für mta-sts.' . $domain . ' bereitstellen.');
        } elseif ($http['status'] !== 200) {
            $this->add('fail', 'technical', 'mtasts.policy_http', 'Die Policy-Datei antwortet mit HTTP ' . $http['status'] . ' (erwartet: 200; Weiterleitungen sind nicht erlaubt).', 'MTA-STS ist wirkungslos.', 'Datei unter dem genannten Pfad ohne Redirect ausliefern.');
        } else {
            $ct = strtolower($http['headers']['content-type'] ?? '');
            if (!str_starts_with($ct, 'text/plain')) {
                $this->add('warn', 'technical', 'mtasts.content_type', 'Content-Type der Policy ist "' . ($ct ?: 'leer') . '" (erwartet: text/plain).', 'Strenge Sender lehnen die Policy ab.', 'Content-Type: text/plain setzen.');
            }
            $policy = $this->parsePolicy($http['body']);
            $details[] = ['label' => 'Modus', 'value' => $policy['mode'] ?? '–'];
            $details[] = ['label' => 'max_age', 'value' => isset($policy['max_age']) ? $policy['max_age'] . ' s (' . round($policy['max_age'] / 86400, 1) . ' Tage)' : '–'];
            $details[] = ['label' => 'mx-Muster', 'value' => implode(', ', $policy['mx']) ?: '–'];
            $this->evaluatePolicy($policy, $mxHosts);
        }
        $status = $this->statusFromFindings();
        $mode = $policy['mode'] ?? null;
        $summary = match (true) {
            $status === 'fail' => 'MTA-STS ist fehlerhaft konfiguriert.',
            $mode === 'enforce' => 'MTA-STS ist aktiv (enforce).',
            $mode === 'testing' => 'MTA-STS ist im Testmodus.',
            default => 'MTA-STS-Record vorhanden.',
        };
        return $this->build('mta-sts', 'MTA-STS', $status, $summary, $records[0], $details, ['policy' => $policy, 'policy_url' => $url, 'id' => $id]);
    }

    /** @return array{version:?string,mode:?string,max_age:?int,mx:string[],errors:string[]} */
    public function parsePolicy(string $body): array
    {
        $p = ['version' => null, 'mode' => null, 'max_age' => null, 'mx' => [], 'errors' => []];
        foreach (preg_split('/\r?\n/', $body) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || !str_contains($line, ':')) {
                continue;
            }
            [$k, $v] = array_map('trim', explode(':', $line, 2));
            switch (strtolower($k)) {
                case 'version':
                    $p['version'] = $v;
                    break;
                case 'mode':
                    $p['mode'] = strtolower($v);
                    break;
                case 'max_age':
                    $p['max_age'] = ctype_digit($v) ? (int) $v : null;
                    break;
                case 'mx':
                    $p['mx'][] = strtolower($v);
                    break;
            }
        }
        if ($p['version'] !== 'STSv1') {
            $p['errors'][] = 'version muss STSv1 sein';
        }
        if (!in_array($p['mode'], ['enforce', 'testing', 'none'], true)) {
            $p['errors'][] = 'mode muss enforce, testing oder none sein';
        }
        if ($p['max_age'] === null) {
            $p['errors'][] = 'max_age fehlt oder ist keine Zahl';
        }
        if ($p['mx'] === [] && $p['mode'] !== 'none') {
            $p['errors'][] = 'mx fehlt';
        }
        return $p;
    }

    private function evaluatePolicy(array $policy, array $mxHosts): void
    {
        foreach ($policy['errors'] as $e) {
            $this->add('fail', 'technical', 'mtasts.policy_syntax', 'Policy-Datei: ' . $e . '.', 'Sender verwerfen eine ungültige Policy.', 'Policy-Datei korrigieren.');
        }
        if ($policy['mode'] === 'testing') {
            $this->add('warn', 'bestpractice', 'mtasts.testing', 'MTA-STS läuft im Modus "testing": Verstöße werden nur gemeldet (TLS-RPT), die Zustellung wird nicht verhindert.', 'Kein Schutz vor Downgrade-Angriffen.', 'Nach erfolgreicher Testphase auf "enforce" stellen.');
        } elseif ($policy['mode'] === 'none') {
            $this->add('info', 'technical', 'mtasts.none', 'Modus "none": MTA-STS ist deaktiviert.', null, null);
        } elseif ($policy['mode'] === 'enforce') {
            $this->add('pass', 'technical', 'mtasts.enforce', 'Modus "enforce": Sender müssen TLS mit gültigem Zertifikat verwenden.', null, null);
        }
        if ($policy['max_age'] !== null && $policy['mode'] === 'enforce' && $policy['max_age'] < 604800) {
            $this->add('warn', 'bestpractice', 'mtasts.max_age_short', "max_age von {$policy['max_age']} s ist kurz (empfohlen: mindestens eine Woche, typisch 1–12 Monate).", 'Der Schutz greift nur kurz nach dem letzten Abruf.', 'max_age erhöhen, z. B. 2592000 (30 Tage).');
        }
        if ($mxHosts !== [] && $policy['mx'] !== [] && $policy['mode'] !== 'none') {
            $uncovered = array_values(array_filter($mxHosts, fn($h) => !$this->covered($h, $policy['mx'])));
            if ($uncovered !== []) {
                $this->add($policy['mode'] === 'enforce' ? 'fail' : 'warn', 'technical', 'mtasts.mx_mismatch', 'MX-Hosts ohne passendes mx-Muster in der Policy: ' . implode(', ', $uncovered) . '.', $policy['mode'] === 'enforce' ? 'Sender liefern an diese Hosts nicht aus → Mails können abgewiesen werden/verloren gehen.' : 'Im Modus enforce würden Mails an diese Hosts nicht zugestellt.', 'mx-Zeilen der Policy mit den tatsächlichen MX-Hosts abgleichen.');
            }
        }
    }

    /** @param string[] $patterns */
    private function covered(string $host, array $patterns): bool
    {
        foreach ($patterns as $p) {
            if ($p === $host) {
                return true;
            }
            if (str_starts_with($p, '*.') && str_ends_with($host, substr($p, 1)) && substr_count($host, '.') >= substr_count($p, '.')) {
                // Wildcard passt auf genau ein Label (RFC 8461 §4.1)
                $prefix = substr($host, 0, -strlen(substr($p, 1)));
                if ($prefix !== '' && !str_contains($prefix, '.')) {
                    return true;
                }
            }
        }
        return false;
    }
}

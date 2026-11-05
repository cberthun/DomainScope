<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;

/**
 * DKIM-Prüfung für bekannte Selektoren. Ein nicht gefundener Selektor beweist nicht, dass kein DKIM
 * eingesetzt wird – DKIM-Selektoren sind nicht per DNS auflistbar.
 */
final class DkimAnalyzer
{
    use CheckBuilder;

    /** Begrenzte Liste verbreiteter Selektoren für die optional aktivierbare Suche. */
    public const COMMON_SELECTORS = [
        'default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'k2', 'k3', 'mail', 'dkim', 'smtp',
        'mandrill', 'mailjet', 'mxvault', 'zoho', 'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3',
        'amazonses', 'sendgrid', 'em', 'mte1', 's1-ionos', 's2-ionos', 'dk1', 'resend', 'cm', 'pm',
    ];

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /**
     * @param string[] $selectors
     * @return array<string,mixed>
     */
    public function analyze(string $domain, array $selectors, bool $autoscan = false): array
    {
        $this->reset();
        $selectors = $this->cleanSelectors($selectors);
        $scanned = false;
        if ($autoscan) {
            $selectors = array_values(array_unique([...$selectors, ...self::COMMON_SELECTORS]));
            $scanned = true;
        }
        if ($selectors === []) {
            $this->add('info', 'technical', 'dkim.no_selectors', 'Es wurden keine Selektoren angegeben. DKIM-Selektoren lassen sich nicht per DNS auflisten.', null, 'Selektor aus dem DKIM-Header einer eigenen Mail ("DKIM-Signature: … s=<selektor>") ermitteln und bei der Domain hinterlegen.');
            return $this->build('dkim', 'DKIM', 'none', 'Kein Selektor zur Prüfung angegeben.', null, [], ['selectors' => [], 'scanned' => false, 'found' => 0]);
        }
        $reqs = [];
        foreach ($selectors as $sel) {
            $reqs[] = ['resolver' => $this->primary(), 'name' => "$sel._domainkey.$domain", 'type' => 'TXT'];
        }
        $results = $this->dns->client()->queryMany($reqs);
        $items = [];
        $found = 0;
        $errors = 0;
        foreach ($selectors as $i => $sel) {
            $r = $results[$i];
            $item = ['selector' => $sel, 'name' => "$sel._domainkey.$domain", 'status' => $r['status'], 'record' => null, 'checks' => [], 'key' => null];
            if (in_array($r['status'], ['timeout', 'error', 'servfail'], true)) {
                $errors++;
                $item['state'] = 'error';
                $item['error'] = $r['error'] ?? $r['status'];
                $items[] = $item;
                continue;
            }
            $txt = [];
            $cname = null;
            foreach ($r['answer'] as $rec) {
                if ($rec['type'] === 'TXT') {
                    $txt[] = $rec['data'];
                } elseif ($rec['type'] === 'CNAME') {
                    $cname = $rec['data'];
                }
            }
            $txt = array_values(array_filter($txt, static fn($v) => preg_match('/(^|;)\s*(v=DKIM1|p=)/i', $v) === 1));
            if ($txt === []) {
                $item['state'] = 'missing';
                $items[] = $item;
                continue;
            }
            $found++;
            $item['state'] = 'found';
            $item['cname'] = $cname;
            $item['record'] = $txt[0];
            $item += $this->inspect($txt[0], $sel);
            $items[] = $item;
        }

        foreach ($items as $it) {
            if (($it['state'] ?? '') !== 'found') {
                continue;
            }
            foreach ($it['issues'] as $issue) {
                $this->add($issue['level'], 'technical', $issue['code'], '[' . $it['selector'] . '] ' . $issue['message'], $issue['impact'] ?? null, $issue['recommendation'] ?? null);
            }
        }
        if ($found === 0) {
            $msg = $scanned
                ? 'Keiner der geprüften ' . count($selectors) . ' Selektoren (inkl. gängiger Standardnamen) liefert einen DKIM-Key. Das schließt andere Selektoren nicht aus.'
                : 'Für die angegebenen Selektoren wurde kein DKIM-Record gefunden.';
            $this->add('info', 'technical', 'dkim.none_found', $msg, 'Eine DKIM-Signatur mit anderem Selektor kann dennoch existieren.', 'Den tatsächlich verwendeten Selektor aus einer Mail ermitteln und prüfen.');
        }
        $status = $found === 0 ? ($errors === count($selectors) ? 'error' : 'none') : $this->statusFromFindings();
        $summary = $found === 0
            ? 'Kein DKIM-Key unter den geprüften Selektoren gefunden (' . count($selectors) . ' geprüft).'
            : "$found von " . count($selectors) . ' geprüften Selektoren liefern einen Key.';
        return $this->build('dkim', 'DKIM', $status, $summary, null, [
            ['label' => 'Geprüfte Selektoren', 'value' => (string) count($selectors)],
            ['label' => 'Gefunden', 'value' => (string) $found],
            ['label' => 'Modus', 'value' => $scanned ? 'Begrenzte Suche mit gängigen Selektoren' : 'Nur angegebene Selektoren'],
        ], ['selectors' => $items, 'scanned' => $scanned, 'found' => $found]);
    }

    private function primary(): string
    {
        return (string) \DomainScope\Support\Config::get('app.dns.default_resolver', 'cloudflare');
    }

    /**
     * @param string[] $in
     * @return string[]
     */
    public function cleanSelectors(array $in): array
    {
        $out = [];
        foreach ($in as $s) {
            $s = strtolower(trim((string) $s));
            if ($s !== '' && preg_match('/^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$/', $s) === 1) {
                $out[$s] = true;
            }
        }
        return array_slice(array_keys($out), 0, 60);
    }

    /** @return array{tags:array<string,string>,key:?array,issues:array} */
    public function inspect(string $record, string $selector): array
    {
        $t = $this->tags($record);
        $issues = [];
        $key = null;
        $issue = static fn(string $level, string $code, string $message, ?string $impact = null, ?string $rec = null) =>
            ['level' => $level, 'code' => $code, 'message' => $message, 'impact' => $impact, 'recommendation' => $rec];

        if (isset($t['v']) && strtoupper($t['v']) !== 'DKIM1') {
            $issues[] = $issue('fail', 'dkim.bad_version', 'Ungültige Version v=' . $t['v'] . ' (erwartet: DKIM1).', 'Der Record wird ignoriert.', 'v=DKIM1 setzen.');
        }
        $k = strtolower($t['k'] ?? 'rsa');
        if (!in_array($k, ['rsa', 'ed25519'], true)) {
            $issues[] = $issue('fail', 'dkim.bad_keytype', "Unbekannter Schlüsseltyp k=$k.", null, 'rsa oder ed25519 verwenden.');
        }
        $p = $t['p'] ?? null;
        if ($p === null) {
            $issues[] = $issue('fail', 'dkim.no_p', 'Das Tag p= (Public Key) fehlt.', 'Signaturen können nicht geprüft werden.', 'Public Key des Mailanbieters eintragen.');
        } elseif (trim($p) === '') {
            $issues[] = $issue('warn', 'dkim.revoked', 'p= ist leer: Der Schlüssel wurde widerrufen.', 'Mit diesem Selektor signierte Mails schlagen fehl.', 'Selektor entfernen oder neuen Schlüssel veröffentlichen.');
            $key = ['type' => $k, 'bits' => null, 'revoked' => true];
        } else {
            $key = $this->parseKey(preg_replace('/\s+/', '', $p) ?? $p, $k);
            if ($key === null) {
                $issues[] = $issue('fail', 'dkim.bad_key', 'Der Public Key ist kein gültiges Base64-/DER-Format.', 'Signaturen können nicht geprüft werden.', 'Key vollständig und ohne Zeilenumbrüche/Anführungszeichen-Fehler übernehmen (lange Keys in mehrere TXT-Strings teilen).');
            } elseif ($key['type'] === 'rsa' && $key['bits'] !== null) {
                if ($key['bits'] < 1024) {
                    $issues[] = $issue('fail', 'dkim.weak_key', "RSA-Schlüssel mit nur {$key['bits']} Bit gilt als unsicher.", 'Der Schlüssel kann mit vertretbarem Aufwand gebrochen werden; viele Empfänger lehnen ihn ab.', 'Neuen Schlüssel mit mindestens 2048 Bit erzeugen.');
                } elseif ($key['bits'] < 2048) {
                    $issues[] = $issue('warn', 'dkim.short_key', "RSA-Schlüssel mit {$key['bits']} Bit (empfohlen: ≥ 2048).", 'Entspricht nicht mehr dem Stand der Technik (RFC 8301: min. 1024, empfohlen 2048).', 'Schlüssel auf 2048 Bit rotieren.');
                }
            }
        }
        $flags = array_map('trim', explode(':', strtolower($t['t'] ?? '')));
        if (in_array('y', $flags, true)) {
            $issues[] = $issue('warn', 'dkim.testing', 'Das Flag t=y (Testmodus) ist gesetzt. Empfänger sollen Fehlschläge nicht wie echte Fehler behandeln.', 'DKIM-Fehler haben keine Konsequenzen.', 'Nach erfolgreichem Test das Flag entfernen.');
        }
        if (in_array('s', $flags, true)) {
            $issues[] = $issue('info', 'dkim.strict_subdomain', 'Flag t=s: Der Schlüssel gilt nur für exakt diese Domain, nicht für Subdomains.');
        }
        if (isset($t['h']) && !preg_match('/(sha256)/i', $t['h']) && preg_match('/sha1/i', $t['h'])) {
            $issues[] = $issue('warn', 'dkim.sha1_only', 'Der Schlüssel erlaubt nur SHA-1 (h=sha1), das als veraltet gilt.', null, 'h=sha256 verwenden.');
        }
        if (isset($t['s']) && !in_array(strtolower($t['s']), ['*', 'email'], true) && !str_contains(strtolower($t['s']), 'email') && !str_contains($t['s'], '*')) {
            $issues[] = $issue('warn', 'dkim.service_type', 'Service-Typ s=' . $t['s'] . ' erlaubt kein E-Mail ("email" oder "*").', 'Mails werden mit diesem Key nicht verifiziert.', 's=* oder s=email setzen.');
        }
        return ['tags' => $t, 'key' => $key, 'issues' => $issues];
    }

    /** @return array{type:string,bits:?int,fingerprint:string}|null */
    private function parseKey(string $b64, string $declared): ?array
    {
        $der = base64_decode($b64, true);
        if ($der === false || $der === '') {
            return null;
        }
        if ($declared === 'ed25519') {
            return strlen($der) === 32 ? ['type' => 'ed25519', 'bits' => 256, 'fingerprint' => substr(hash('sha256', $der), 0, 16)] : null;
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($b64, 64, "\n") . "-----END PUBLIC KEY-----\n";
        $pk = @openssl_pkey_get_public($pem);
        if ($pk === false) {
            return null;
        }
        $d = openssl_pkey_get_details($pk);
        if (!$d) {
            return null;
        }
        $type = match ($d['type'] ?? -1) {
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_EC => 'ec',
            default => 'other',
        };
        return ['type' => $type, 'bits' => $d['bits'] ?? null, 'fingerprint' => substr(hash('sha256', $der), 0, 16)];
    }
}

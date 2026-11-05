<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;
use DomainScope\Validation\PublicSuffix;

/** DMARC-Analyse nach RFC 7489 (inkl. np= aus RFC 9091 / DMARCbis). */
final class DmarcAnalyzer
{
    use CheckBuilder;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /** @return array<string,mixed> */
    public function analyze(string $domain, ?array $spf = null): array
    {
        $this->reset();
        $lookupName = '_dmarc.' . $domain;
        $res = $this->dns->txtWithPrefix($lookupName, 'v=DMARC1');
        $inherited = false;
        if (in_array($res['status'], ['timeout', 'error', 'servfail'], true)) {
            return $this->build('dmarc', 'DMARC', 'error', 'DMARC konnte nicht geprüft werden: ' . ($res['error'] ?? $res['status']), null);
        }
        $records = array_values(array_filter($res['values'], static fn($v) => preg_match('/^v=DMARC1\s*(;|$)/i', trim($v)) === 1));
        $org = PublicSuffix::registrable($domain);
        if ($records === [] && $org !== null && $org !== $domain) {
            // RFC 7489 §6.6.3: Fallback auf die Organizational Domain
            $res2 = $this->dns->txtWithPrefix('_dmarc.' . $org, 'v=DMARC1');
            $records = array_values(array_filter($res2['values'], static fn($v) => preg_match('/^v=DMARC1\s*(;|$)/i', trim($v)) === 1));
            if ($records !== []) {
                $inherited = true;
                $lookupName = '_dmarc.' . $org;
            }
        }
        if ($records === []) {
            $this->add('info', 'technical', 'dmarc.missing', 'Es wurde kein DMARC-Record unter _dmarc.' . $domain . ' gefunden.', 'Empfänger haben keine Anweisung, wie mit SPF/DKIM-Fehlschlägen umzugehen ist; Domain-Spoofing wird nicht unterbunden.', 'TXT-Record _dmarc mit "v=DMARC1; p=none; rua=mailto:…" anlegen, Reports auswerten und schrittweise auf quarantine/reject erhöhen.');
            return $this->build('dmarc', 'DMARC', 'none', 'Kein DMARC-Record gefunden.', null);
        }
        if (count($records) > 1) {
            $this->add('fail', 'technical', 'dmarc.multiple', 'Es existieren ' . count($records) . ' DMARC-Records. Empfänger ignorieren DMARC dann vollständig.', 'DMARC ist faktisch unwirksam.', 'Nur einen DMARC-Record behalten.');
        }
        $record = $records[0];
        $t = $this->tags($record);
        $details = [];

        if ($inherited) {
            $this->add('info', 'technical', 'dmarc.inherited', "Für $domain existiert kein eigener Record; die Policy der Organisationsdomain $org gilt (Fallback nach RFC 7489).", null, null);
        }

        // Reihenfolge: v muss erstes Tag sein, p früh
        if (!preg_match('/^\s*v=DMARC1\s*;/i', $record)) {
            $this->add('warn', 'technical', 'dmarc.syntax_v', 'Der Record sollte mit "v=DMARC1;" beginnen.', null, 'Syntax korrigieren.');
        }
        $p = strtolower($t['p'] ?? '');
        $sp = strtolower($t['sp'] ?? '');
        $np = strtolower($t['np'] ?? '');
        $valid = ['none', 'quarantine', 'reject'];
        if ($p === '') {
            $this->add('fail', 'technical', 'dmarc.no_p', 'Das Pflicht-Tag p= fehlt. Ohne gültige Policy (und ohne rua=) wird der Record ignoriert.', 'DMARC ist unwirksam.', 'p=none, p=quarantine oder p=reject setzen.');
        } elseif (!in_array($p, $valid, true)) {
            $this->add('fail', 'technical', 'dmarc.bad_p', "Ungültiger Wert p=$p.", 'Der Record wird nicht als gültig gewertet.', 'Erlaubt: none, quarantine, reject.');
        } elseif ($p === 'none') {
            $this->add('warn', 'technical', 'dmarc.p_none', 'Policy p=none: Fehlschläge werden nur gemeldet, nicht behandelt (Monitoring-Modus).', 'Gefälschte Mails im Namen der Domain werden weiterhin zugestellt.', 'Nach Auswertung der Reports auf p=quarantine und später p=reject erhöhen.');
        } elseif ($p === 'quarantine') {
            $this->add('pass', 'technical', 'dmarc.p_quarantine', 'Policy p=quarantine: Nicht authentifizierte Mails sollen als verdächtig behandelt werden.', null, 'Optional auf p=reject erhöhen, wenn alle legitimen Absender abgedeckt sind.');
        } else {
            $this->add('pass', 'technical', 'dmarc.p_reject', 'Policy p=reject: Nicht authentifizierte Mails sollen abgelehnt werden.', null, null);
        }
        $details[] = ['label' => 'p (Domain-Policy)', 'value' => $p ?: '–'];

        if ($sp !== '') {
            if (!in_array($sp, $valid, true)) {
                $this->add('fail', 'technical', 'dmarc.bad_sp', "Ungültiger Wert sp=$sp.", null, 'Erlaubt: none, quarantine, reject.');
            } elseif ($this->weaker($sp, $p)) {
                $this->add('warn', 'bestpractice', 'dmarc.sp_weaker', "Subdomain-Policy sp=$sp ist schwächer als p=$p.", 'Subdomains lassen sich leichter fälschen.', 'sp entfernen oder auf dieselbe Stufe wie p setzen.');
            }
        }
        $details[] = ['label' => 'sp (Subdomain-Policy)', 'value' => $sp !== '' ? $sp : ('nicht gesetzt → erbt p=' . ($p ?: '–'))];
        if ($np !== '') {
            if (!in_array($np, $valid, true)) {
                $this->add('warn', 'technical', 'dmarc.bad_np', "Ungültiger Wert np=$np.", null, 'Erlaubt: none, quarantine, reject.');
            }
            $details[] = ['label' => 'np (nicht existente Subdomains)', 'value' => $np];
        } else {
            $details[] = ['label' => 'np (nicht existente Subdomains)', 'value' => 'nicht gesetzt'];
        }

        $pct = $t['pct'] ?? '100';
        if (!ctype_digit($pct) || (int) $pct > 100) {
            $this->add('fail', 'technical', 'dmarc.bad_pct', "Ungültiger Wert pct=$pct (erlaubt: 0–100).", null, 'pct korrigieren.');
        } elseif ((int) $pct < 100 && $p !== 'none') {
            $this->add('warn', 'technical', 'dmarc.pct', "pct=$pct: Die Policy gilt nur für $pct % der Nachrichten.", 'Ein Teil der gefälschten Mails wird nicht behandelt.', 'Nach der Einführungsphase pct=100 setzen (Standardwert).');
        }
        $details[] = ['label' => 'pct', 'value' => $pct . ' %'];

        foreach (['adkim' => 'DKIM', 'aspf' => 'SPF'] as $tag => $label) {
            $v = strtolower($t[$tag] ?? '');
            if ($v !== '' && !in_array($v, ['r', 's'], true)) {
                $this->add('fail', 'technical', "dmarc.bad_$tag", "Ungültiger Wert $tag=$v (erlaubt: r, s).", null, "$tag korrigieren.");
            }
            $mode = $v === 's' ? 'strict (exakter Domain-Match)' : 'relaxed (Organisationsdomain genügt)' . ($v === '' ? ' – Standard' : '');
            $details[] = ['label' => "$tag ($label-Alignment)", 'value' => $mode];
        }
        if (!empty($t['fo'])) {
            $details[] = ['label' => 'fo', 'value' => $t['fo']];
        }
        $details[] = ['label' => 'ri', 'value' => $t['ri'] ?? '86400 (Standard)'];

        $rua = $this->uris($t['rua'] ?? '');
        $ruf = $this->uris($t['ruf'] ?? '');
        $details[] = ['label' => 'rua (Aggregate-Reports)', 'value' => $rua ? implode(', ', array_column($rua, 'raw')) : '–'];
        $details[] = ['label' => 'ruf (Forensic-Reports)', 'value' => $ruf ? implode(', ', array_column($ruf, 'raw')) : '–'];
        if ($rua === []) {
            $this->add('info', 'bestpractice', 'dmarc.no_rua', 'Es ist kein rua= konfiguriert: Aggregate-Reports werden nicht zugestellt.', 'Ohne Reports bleibt unklar, welche Quellen im Namen der Domain senden.', 'rua=mailto:dmarc@' . $domain . ' ergänzen.');
        }
        $ext = 0;
        foreach (array_merge($rua, $ruf) as $u) {
            if ($u['scheme'] === 'mailto' && $u['host'] !== null && !$this->sameOrg($u['host'], $domain)) {
                if (++$ext > 4) {
                    break;
                }
                $auth = $this->dns->txtWithPrefix($domain . '._report._dmarc.' . $u['host'], 'v=DMARC1');
                if ($auth['values'] === []) {
                    $this->add('warn', 'technical', 'dmarc.external_unauthorized', "Report-Ziel {$u['raw']} liegt bei einer fremden Domain, die das Empfangen nicht per {$domain}._report._dmarc.{$u['host']} autorisiert hat.", 'Reports werden von konformen Absendern nicht dorthin gesendet.', 'Der Betreiber von ' . $u['host'] . ' muss einen TXT-Record "v=DMARC1" unter dem genannten Namen veröffentlichen.');
                }
            }
            if (!in_array($u['scheme'], ['mailto', 'https'], true)) {
                $this->add('warn', 'technical', 'dmarc.bad_uri', "Ungültiges Report-URI-Schema: {$u['raw']}", null, 'mailto: oder https: verwenden.');
            }
        }
        if ($ruf !== []) {
            $this->add('info', 'bestpractice', 'dmarc.ruf', 'ruf= (Forensic-Reports) wird von vielen Empfängern nicht mehr ausgewertet und kann personenbezogene Daten enthalten.', null, 'Nur einsetzen, wenn zwingend nötig.');
        }

        // Alignment-Hinweis anhand SPF-Ergebnis
        if ($spf !== null && in_array($spf['status'] ?? '', ['none', 'fail'], true) && ($spf['status'] === 'none')) {
            $this->add('info', 'technical', 'dmarc.no_spf', 'Ohne SPF-Record ist DMARC nur über DKIM erfüllbar.', 'Mails ohne gültige DKIM-Signatur mit Domain-Alignment schlagen DMARC fehl.', 'SPF und DKIM einrichten.');
        }

        $status = $this->statusFromFindings();
        $summary = match (true) {
            $status === 'fail' => 'DMARC-Record ist fehlerhaft.',
            $p === 'reject' => 'DMARC ist mit p=reject konfiguriert.',
            $p === 'quarantine' => 'DMARC ist mit p=quarantine konfiguriert.',
            default => 'DMARC ist vorhanden, erzwingt aber nichts (p=' . ($p ?: '?') . ').',
        };
        return $this->build('dmarc', 'DMARC', $status, $summary, $record, $details, [
            'tags' => $t, 'policy' => $p, 'subdomain_policy' => $sp ?: $p, 'inherited' => $inherited, 'lookup_name' => $lookupName,
            'enforcing' => in_array($p, ['quarantine', 'reject'], true) && (int) $pct === 100,
        ]);
    }

    private function weaker(string $a, string $b): bool
    {
        $rank = ['none' => 0, 'quarantine' => 1, 'reject' => 2];
        return ($rank[$a] ?? 0) < ($rank[$b] ?? 0);
    }

    private function sameOrg(string $host, string $domain): bool
    {
        return PublicSuffix::registrable($host) === PublicSuffix::registrable($domain);
    }

    /** @return array<int,array{raw:string,scheme:string,host:?string}> */
    public function uris(string $value): array
    {
        $out = [];
        foreach (explode(',', $value) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            $raw = preg_replace('/![0-9]+[kmgt]?$/i', '', $part) ?? $part;
            $scheme = strtolower((string) strstr($raw, ':', true));
            $host = null;
            if ($scheme === 'mailto' && preg_match('/@([^@>\s]+)$/', $raw, $m)) {
                $host = strtolower($m[1]);
            } elseif ($scheme === 'https') {
                $host = strtolower((string) parse_url($raw, PHP_URL_HOST));
            }
            $out[] = ['raw' => $part, 'scheme' => $scheme, 'host' => $host];
        }
        return $out;
    }
}

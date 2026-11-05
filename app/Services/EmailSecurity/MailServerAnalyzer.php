<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;
use DomainScope\Services\DNS\RecordFormatter;
use DomainScope\Validation\IpClassifier;

/** MX-Records, Adressen der Mailserver und PTR-Konsistenz (Forward-confirmed reverse DNS). */
final class MailServerAnalyzer
{
    use CheckBuilder;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /** @return array<string,mixed> */
    public function analyze(string $domain): array
    {
        $this->reset();
        $mx = $this->dns->values($domain, 'MX');
        if (in_array($mx['status'], ['timeout', 'error', 'servfail'], true)) {
            return $this->build('mx', 'MX & PTR', 'error', 'MX-Records konnten nicht abgefragt werden: ' . ($mx['error'] ?? $mx['status']), null, [], ['hosts' => []]);
        }
        $hosts = [];
        $nullMx = false;
        foreach ($mx['records'] as $rec) {
            $p = RecordFormatter::parseMx($rec['data']);
            if ($p === null) {
                continue;
            }
            if ($p['host'] === '' || $p['host'] === '.') {
                $nullMx = true;
                continue;
            }
            $hosts[] = $p + ['ttl' => $rec['ttl']];
        }
        usort($hosts, static fn($a, $b) => $a['priority'] <=> $b['priority'] ?: strcmp($a['host'], $b['host']));

        if ($hosts === [] && $nullMx) {
            $this->add('pass', 'technical', 'mx.null', 'Null-MX (RFC 7505) gesetzt: Die Domain deklariert, keine Mails zu empfangen.', null, null);
            return $this->build('mx', 'MX & PTR', 'pass', 'Domain empfängt keine E-Mails (Null-MX).', null, [], ['hosts' => [], 'null_mx' => true]);
        }
        if ($hosts === []) {
            $a = $this->dns->values($domain, 'A');
            $aaaa = $this->dns->values($domain, 'AAAA');
            $implicit = $a['values'] !== [] || $aaaa['values'] !== [];
            $this->add('info', 'technical', 'mx.missing', 'Keine MX-Records vorhanden.' . ($implicit ? ' Mailserver nehmen ersatzweise den A/AAAA-Record der Domain (impliziter MX, RFC 5321).' : ''), 'Eingehende Mails können nicht (oder nur unerwartet) zugestellt werden.', 'Bei Mailempfang MX-Records anlegen; sonst Null-MX ("0 .") veröffentlichen.');
            return $this->build('mx', 'MX & PTR', 'none', 'Keine MX-Records.', null, [], ['hosts' => [], 'implicit_mx' => $implicit]);
        }

        $out = [];
        $ipBudget = 8;
        foreach (array_slice($hosts, 0, 10) as $h) {
            $entry = $h + ['addresses' => [], 'cname' => null, 'ptr' => []];
            $c = $this->dns->get($h['host'], 'A');
            $aaaa = $this->dns->get($h['host'], 'AAAA');
            foreach ([$c, $aaaa] as $r) {
                foreach ($r['answer'] as $rec) {
                    if ($rec['type'] === 'CNAME') {
                        $entry['cname'] = $rec['data'];
                    }
                    if (in_array($rec['type'], ['A', 'AAAA'], true)) {
                        $entry['addresses'][] = $rec['data'];
                    }
                }
            }
            $entry['addresses'] = array_values(array_unique($entry['addresses']));
            if ($entry['cname'] !== null) {
                $this->add('fail', 'technical', 'mx.cname', "MX-Host {$h['host']} ist ein CNAME (→ {$entry['cname']}). MX-Ziele dürfen laut RFC 2181 §10.3 keine Aliase sein.", 'Manche Mailserver liefern nicht an CNAME-MX-Ziele aus.', 'MX direkt auf den A/AAAA-Namen zeigen lassen.');
            }
            if ($entry['addresses'] === []) {
                $st = [$c['status'], $aaaa['status']];
                $isErr = (bool) array_intersect($st, ['timeout', 'error', 'servfail']);
                $this->add($isErr ? 'warn' : 'fail', 'technical', 'mx.unresolvable', "MX-Host {$h['host']} " . ($isErr ? 'konnte nicht aufgelöst werden (DNS-Fehler).' : 'hat keine A/AAAA-Records.'), $isErr ? null : 'Mails an diesen MX können nicht zugestellt werden.', $isErr ? 'Prüfung wiederholen.' : 'Adressrecord für den MX-Host anlegen oder den MX entfernen.');
            }
            foreach ($entry['addresses'] as $ip) {
                $cls = IpClassifier::classify($ip);
                if (!$cls['public']) {
                    $this->add('fail', 'technical', 'mx.private_ip', "MX-Host {$h['host']} zeigt auf $ip ({$cls['label']}) – aus dem Internet nicht erreichbar.", null, 'Auf eine öffentliche Adresse zeigen lassen.');
                }
            }
            foreach (array_slice($entry['addresses'], 0, 2) as $ip) {
                if ($ipBudget-- <= 0 || !IpClassifier::isPublic($ip) || ($rev = IpClassifier::reverseName($ip)) === null) {
                    continue;
                }
                $ptr = $this->dns->values($rev, 'PTR');
                $names = $ptr['values'];
                $fcrdns = false;
                foreach (array_slice($names, 0, 2) as $n) {
                    $fwd = $this->dns->values($n, str_contains($ip, ':') ? 'AAAA' : 'A');
                    $norm = array_map(static fn($x) => IpClassifier::normalize($x) ?? $x, $fwd['values']);
                    if (in_array(IpClassifier::normalize($ip), $norm, true)) {
                        $fcrdns = true;
                    }
                }
                $entry['ptr'][] = ['ip' => $ip, 'names' => $names, 'fcrdns' => $fcrdns, 'status' => $ptr['status']];
                if ($names === [] && !in_array($ptr['status'], ['timeout', 'error', 'servfail'], true)) {
                    $this->add('warn', 'bestpractice', 'mx.ptr_missing', "Für $ip ({$h['host']}) existiert kein PTR-Record.", 'Viele Mailserver bewerten fehlendes Reverse-DNS negativ; für ausgehende Mails kritisch, für reinen Empfang weniger.', 'Beim Hoster/Provider einen PTR-Eintrag setzen lassen, der auf den Mailserver-Namen zeigt.');
                } elseif ($names !== [] && !$fcrdns) {
                    $this->add('warn', 'bestpractice', 'mx.ptr_mismatch', "PTR von $ip (" . implode(', ', array_slice($names, 0, 2)) . ') löst nicht zurück auf dieselbe IP auf (kein FCrDNS).', 'Reverse-DNS und Forward-DNS stimmen nicht überein; kann Spam-Scores verschlechtern.', 'PTR und A/AAAA-Record des Mailservernamens abstimmen.');
                }
            }
            $out[] = $entry;
        }
        if (count($hosts) === 1) {
            $this->add('info', 'bestpractice', 'mx.single', 'Es ist nur ein MX-Host konfiguriert (kein Fallback).', null, 'Bei Bedarf einen zweiten MX ergänzen.');
        }
        $status = $this->statusFromFindings();
        return $this->build('mx', 'MX & PTR', $status, count($out) . ' MX-Host(s) geprüft.', null, [], ['hosts' => $out, 'null_mx' => false]);
    }
}

<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

use DomainScope\Services\DNS\DnsLookup;
use DomainScope\Services\DNS\RecordFormatter;

/**
 * SPF-Analyse nach RFC 7208: Syntax, mehrere Records, Include-/Redirect-Rekursion, Zyklen,
 * DNS-Lookup-Limit (10), Void-Lookup-Limit (2) und abschließende Policy.
 */
final class SpfAnalyzer
{
    public const LOOKUP_LIMIT = 10;
    public const VOID_LIMIT = 2;
    private const MAX_DEPTH = 12;

    /** @var array<string,string[]> */
    private array $recordCache = [];
    private int $lookups = 0;
    private int $voids = 0;
    /** @var array<int,array{level:string,kind:string,message:string,impact?:string,recommendation?:string}> */
    private array $findings = [];
    /** @var string[] */
    private array $permErrors = [];
    private bool $truncated = false;

    public function __construct(private readonly DnsLookup $dns)
    {
    }

    /** @return array<string,mixed> */
    public function analyze(string $domain): array
    {
        $this->recordCache = [];
        $this->lookups = $this->voids = 0;
        $this->findings = [];
        $this->permErrors = [];
        $this->truncated = false;

        $fetch = $this->fetchRecords($domain);
        if ($fetch['status'] === 'timeout' || $fetch['status'] === 'error' || $fetch['status'] === 'servfail') {
            return $this->result('error', 'SPF konnte nicht geprüft werden: ' . ($fetch['error'] ?? 'DNS-Fehler (' . $fetch['status'] . ').'), null, [], null);
        }
        $records = $fetch['records'];
        if ($records === []) {
            $this->add(
                'info', 'technical', 'spf.missing',
                'Unter ' . $domain . ' existiert kein TXT-Record mit v=spf1.',
                'Empfänger können nicht prüfen, welche Server für diese Domain senden dürfen.',
                'Einen SPF-Record anlegen (z. B. "v=spf1 mx -all"). Falls die Domain keine Mails versendet: "v=spf1 -all".'
            );
            return $this->result('none', 'Kein SPF-Record gefunden.', null, [], null);
        }
        if (count($records) > 1) {
            $this->perm('spf.multiple', 'Es existieren ' . count($records) . ' SPF-Records. Nach RFC 7208 §4.5 führt das zu PermError – SPF schlägt für alle Empfänger fehl.', 'Alle SPF-Informationen in einem einzigen Record zusammenführen und die übrigen löschen.');
        }
        $root = $this->walk($domain, $records[0], 0, [$domain]);

        $policy = $this->finalPolicy($root);
        $this->evaluatePolicy($policy, $root);

        if ($this->lookups > self::LOOKUP_LIMIT) {
            $this->perm('spf.lookup_limit', "Der Record verursacht {$this->lookups} DNS-Lookups (Limit: " . self::LOOKUP_LIMIT . '). Empfänger brechen mit PermError ab.', 'Includes reduzieren, Mechanismen durch ip4:/ip6: ersetzen oder ein SPF-Flattening-Verfahren einsetzen.');
        } elseif ($this->lookups >= self::LOOKUP_LIMIT - 1) {
            $this->add('warn', 'technical', 'spf.lookup_near_limit', "{$this->lookups} von " . self::LOOKUP_LIMIT . ' erlaubten DNS-Lookups genutzt.', 'Neue Include-Dienste führen schnell zum PermError.', 'Lookups reduzieren, bevor weitere Dienste hinzugefügt werden.');
        }
        if ($this->voids > self::VOID_LIMIT) {
            $this->perm('spf.void_limit', "{$this->voids} Lookups liefern keine Daten (Void-Lookups, Limit: " . self::VOID_LIMIT . ').', 'Veraltete Mechanismen (a, mx, include auf nicht existierende Namen) entfernen.');
        }
        if ($this->truncated) {
            $this->add('info', 'technical', 'spf.truncated', 'Die Analyse wurde wegen des Abfragebudgets bzw. der Tiefenbegrenzung abgebrochen; die Lookup-Zahl ist ein Mindestwert.', null, null);
        }

        $status = 'pass';
        foreach ($this->findings as $f) {
            if ($f['level'] === 'fail') {
                $status = 'fail';
                break;
            }
            if ($f['level'] === 'warn') {
                $status = 'warn';
            }
        }
        $summary = match ($status) {
            'fail' => $this->permErrors ? 'SPF ist fehlerhaft (PermError-Risiko).' : 'SPF-Policy ist unsicher konfiguriert.',
            'warn' => 'SPF ist vorhanden, hat aber Verbesserungspotenzial.',
            default => 'SPF ist korrekt konfiguriert.',
        };
        return $this->result($status, $summary, $records[0], $this->describe($root), $policy) + ['tree' => $root];
    }

    /** @return array{status:string,records:string[],error:?string} */
    private function fetchRecords(string $domain): array
    {
        if (isset($this->recordCache[$domain])) {
            return ['status' => 'ok', 'records' => $this->recordCache[$domain], 'error' => null];
        }
        $r = $this->dns->txtWithPrefix($domain, 'v=spf1');
        $recs = array_values(array_filter($r['values'], static fn($v) => preg_match('/^v=spf1(\s|$)/i', trim($v)) === 1));
        if (!in_array($r['status'], ['timeout', 'error', 'servfail'], true)) {
            $this->recordCache[$domain] = $recs;
        }
        return ['status' => $r['status'], 'records' => $recs, 'error' => $r['error']];
    }

    /**
     * @param string[] $path
     * @return array<string,mixed>
     */
    private function walk(string $domain, string $record, int $depth, array $path): array
    {
        $node = ['domain' => $domain, 'record' => $record, 'terms' => [], 'error' => null, 'lookups' => 0, 'all' => null, 'redirect' => null];
        $parsed = $this->parse($record);
        foreach ($parsed['errors'] as $err) {
            $this->perm('spf.syntax', "Syntaxfehler in SPF-Record von $domain: $err", 'Den Record korrigieren; fehlerhafte Terme führen zu PermError.');
        }
        if (strlen($record) > 450) {
            $this->add('warn', 'technical', 'spf.long_record', 'Der SPF-Record von ' . $domain . ' ist ' . strlen($record) . ' Zeichen lang (>450). Er kann bei UDP-DNS abgeschnitten werden.', null, 'Record kürzen oder Includes konsolidieren.');
        }
        $hasAll = false;
        foreach ($parsed['terms'] as $term) {
            if ($hasAll && $term['kind'] === 'mechanism') {
                $term['unreachable'] = true;
                $node['terms'][] = $term;
                continue;
            }
            if ($term['kind'] === 'modifier') {
                if ($term['name'] === 'redirect') {
                    $node['redirect'] = $term;
                }
                $node['terms'][] = $term;
                continue;
            }
            if ($term['mechanism'] === 'all') {
                $hasAll = true;
                $node['all'] = $term['qualifier'];
                $node['terms'][] = $term;
                continue;
            }
            $node['terms'][] = $this->evaluateMechanism($term, $domain, $depth, $path, $node);
        }
        if ($hasAll && $node['redirect'] !== null) {
            $this->add('info', 'technical', 'spf.redirect_ignored', "In $domain wird redirect= ignoriert, weil der Record einen all-Mechanismus enthält.", null, 'redirect= entfernen.');
            $node['redirect']['ignored'] = true;
        } elseif ($node['redirect'] !== null) {
            $idx = array_search($node['redirect'], $node['terms'], true);
            $node['terms'][$idx] = $this->evaluateRedirect($node['redirect'], $domain, $depth, $path, $node);
            $node['redirect'] = $node['terms'][$idx];
        }
        return $node;
    }

    /** @return array<string,mixed> */
    private function evaluateMechanism(array $term, string $domain, int $depth, array $path, array &$node): array
    {
        $m = $term['mechanism'];
        $term['lookups'] = 0;
        $term['children'] = null;
        switch ($m) {
            case 'include':
                $target = $term['value'] ?? '';
                $this->count($node, $term);
                if ($target === '') {
                    break;
                }
                if (str_contains($target, '%')) {
                    $term['note'] = 'Makro im Ziel – statisch nicht auflösbar';
                    break;
                }
                $term['children'] = $this->descend($target, $depth, $path, 'include');
                break;
            case 'a':
            case 'mx':
                $this->count($node, $term);
                $name = ($term['value'] ?? '') !== '' ? $term['value'] : $domain;
                if (str_contains($name, '%')) {
                    $term['note'] = 'Makro im Ziel – statisch nicht auflösbar';
                    break;
                }
                $term['resolved'] = $this->resolveAddressMechanism($m, $name, $term);
                break;
            case 'ptr':
                $this->count($node, $term);
                $this->add('warn', 'bestpractice', 'spf.ptr', 'Der Mechanismus "ptr" ist laut RFC 7208 veraltet (langsam, unzuverlässig).', 'Viele Empfänger ignorieren ptr oder behandeln ihn als Fehler.', 'ptr durch ip4:/ip6:/include: ersetzen.');
                break;
            case 'exists':
                $this->count($node, $term);
                if (str_contains((string) ($term['value'] ?? ''), '%')) {
                    $term['note'] = 'Makro-basiert (üblich bei DNSBL-/Reputationsdiensten) – nicht statisch auflösbar';
                }
                break;
            case 'ip4':
            case 'ip6':
                $this->checkIpTerm($term);
                break;
        }
        return $term;
    }

    /** @return array<string,mixed> */
    private function evaluateRedirect(array $term, string $domain, int $depth, array $path, array &$node): array
    {
        $this->count($node, $term);
        $target = $term['value'] ?? '';
        $term['children'] = null;
        if ($target === '') {
            $this->perm('spf.syntax', 'redirect= ohne Zieldomain.', 'Zieldomain angeben oder redirect entfernen.');
        } elseif (!str_contains($target, '%')) {
            $term['children'] = $this->descend($target, $depth, $path, 'redirect');
        }
        return $term;
    }

    /** @return array<string,mixed>|null */
    private function descend(string $target, int $depth, array $path, string $via): ?array
    {
        $target = strtolower(rtrim($target, '.'));
        if (in_array($target, $path, true)) {
            $this->perm('spf.loop', 'Zyklische Abhängigkeit: ' . implode(' → ', [...$path, $target]) . '.', 'Die zirkuläre Referenz auflösen.');
            return ['domain' => $target, 'record' => null, 'terms' => [], 'error' => 'Zyklus', 'lookups' => 0, 'all' => null, 'redirect' => null];
        }
        if ($depth + 1 > self::MAX_DEPTH || $this->dns->budgetExhausted()) {
            $this->truncated = true;
            return ['domain' => $target, 'record' => null, 'terms' => [], 'error' => 'Analyse abgebrochen (Tiefe/Budget)', 'lookups' => 0, 'all' => null, 'redirect' => null];
        }
        $f = $this->fetchRecords($target);
        if (in_array($f['status'], ['timeout', 'error', 'servfail'], true)) {
            $this->add('warn', 'technical', 'spf.include_unreachable', "Das $via-Ziel $target konnte nicht abgefragt werden (" . ($f['error'] ?? $f['status']) . ').', 'Der tatsächliche Lookup-Verbrauch ist unbekannt.', 'Prüfung wiederholen.');
            return ['domain' => $target, 'record' => null, 'terms' => [], 'error' => 'DNS-Fehler: ' . ($f['error'] ?? $f['status']), 'lookups' => 0, 'all' => null, 'redirect' => null];
        }
        if ($f['status'] === 'nxdomain') {
            $this->voids++;
            $this->perm('spf.include_missing', "Das $via-Ziel $target existiert nicht (NXDOMAIN). Bei einem include führt das zu PermError.", "Den toten $via-Eintrag entfernen oder die Zieldomain korrigieren.");
            return ['domain' => $target, 'record' => null, 'terms' => [], 'error' => 'NXDOMAIN', 'lookups' => 0, 'all' => null, 'redirect' => null];
        }
        if ($f['records'] === []) {
            $this->voids++;
            $this->perm('spf.include_no_record', "Das $via-Ziel $target hat keinen SPF-Record. Das führt zu PermError.", "Den $via-Eintrag entfernen oder den Anbieter prüfen.");
            return ['domain' => $target, 'record' => null, 'terms' => [], 'error' => 'kein SPF-Record', 'lookups' => 0, 'all' => null, 'redirect' => null];
        }
        if (count($f['records']) > 1) {
            $this->perm('spf.multiple', "Das $via-Ziel $target veröffentlicht mehrere SPF-Records (PermError).", 'Den Betreiber der Zieldomain informieren bzw. den Eintrag entfernen.');
        }
        return $this->walk($target, $f['records'][0], $depth + 1, [...$path, $target]);
    }

    /** @return array<string,mixed> */
    private function resolveAddressMechanism(string $mech, string $name, array &$term): array
    {
        if ($mech === 'a') {
            $a = $this->dns->values($name, 'A');
            $addrs = $a['values'];
            if ($addrs === []) {
                $aaaa = $this->dns->values($name, 'AAAA');
                $addrs = $aaaa['values'];
            }
            if ($addrs === [] && !in_array($a['status'], ['timeout', 'error', 'servfail'], true)) {
                $this->voids++;
                $this->add('warn', 'technical', 'spf.void_a', "Der a-Mechanismus für $name liefert keine Adresse (Void-Lookup).", 'Zählt zum Void-Limit von 2.', 'Mechanismus entfernen oder DNS korrigieren.');
            }
            return ['hosts' => [$name], 'addresses' => $addrs];
        }
        $mx = $this->dns->values($name, 'MX');
        $hosts = [];
        foreach ($mx['records'] as $rec) {
            $p = RecordFormatter::parseMx($rec['data']);
            if ($p && $p['host'] !== '') {
                $hosts[] = $p['host'];
            }
        }
        if ($hosts === [] && !in_array($mx['status'], ['timeout', 'error', 'servfail'], true)) {
            $this->voids++;
            $this->add('warn', 'technical', 'spf.void_mx', "Der mx-Mechanismus für $name findet keine MX-Records (Void-Lookup).", 'Zählt zum Void-Limit von 2.', 'Mechanismus entfernen.');
        }
        if (count($hosts) > 10) {
            $this->perm('spf.mx_limit', "Der mx-Mechanismus für $name verweist auf " . count($hosts) . ' MX-Hosts (max. 10 erlaubt).', 'Anzahl der MX-Records reduzieren.');
        }
        return ['hosts' => $hosts, 'addresses' => []];
    }

    private function checkIpTerm(array $term): void
    {
        $v = (string) ($term['value'] ?? '');
        $cidr = null;
        if (str_contains($v, '/')) {
            [$v, $cidr] = explode('/', $v, 2);
        }
        $isV4 = $term['mechanism'] === 'ip4';
        if (filter_var($v, FILTER_VALIDATE_IP, $isV4 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6) === false) {
            $this->perm('spf.syntax', "Ungültige Adresse in {$term['mechanism']}:{$term['value']}.", 'Adresse korrigieren.');
            return;
        }
        if ($cidr !== null) {
            $max = $isV4 ? 32 : 128;
            if (!ctype_digit($cidr) || (int) $cidr > $max) {
                $this->perm('spf.syntax', "Ungültige Präfixlänge in {$term['mechanism']}:{$term['value']}.", 'Präfixlänge korrigieren.');
                return;
            }
            $wide = $isV4 ? (int) $cidr <= 15 : (int) $cidr <= 32;
            if ($wide) {
                $this->add('warn', 'bestpractice', 'spf.wide_range', "{$term['mechanism']}:{$term['value']} autorisiert einen sehr großen Adressbereich.", 'Jeder Host in diesem Bereich darf als Absender auftreten.', 'Bereich auf tatsächlich genutzte Server einschränken.');
            }
        }
    }

    /** @return array{terms:array<int,array<string,mixed>>,errors:string[]} */
    public function parse(string $record): array
    {
        $tokens = preg_split('/\s+/', trim($record)) ?: [];
        array_shift($tokens); // v=spf1
        $terms = [];
        $errors = [];
        $seenModifiers = [];
        foreach ($tokens as $tok) {
            if ($tok === '') {
                continue;
            }
            if (preg_match('/^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$/', $tok, $m)) {
                $name = strtolower($m[1]);
                if (in_array($name, ['redirect', 'exp'], true) && isset($seenModifiers[$name])) {
                    $errors[] = "Modifier $name ist mehrfach vorhanden.";
                }
                $seenModifiers[$name] = true;
                $terms[] = ['kind' => 'modifier', 'name' => $name, 'value' => rtrim($m[2], '.'), 'raw' => $tok];
                continue;
            }
            if (!preg_match('/^([+\-~?])?([A-Za-z0-9]+)(?::([^\s\/]+))?(\/\d+)?(\/\/\d+)?$/', $tok, $m)) {
                if (preg_match('/^([+\-~?])?(ip4|ip6):(.+)$/i', $tok, $mm)) {
                    $terms[] = ['kind' => 'mechanism', 'mechanism' => strtolower($mm[2]), 'qualifier' => $mm[1] ?: '+', 'value' => $mm[3], 'raw' => $tok];
                    continue;
                }
                $errors[] = "Unbekannter oder fehlerhafter Term „{$tok}“.";
                continue;
            }
            $mech = strtolower($m[2]);
            if (!in_array($mech, ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'], true)) {
                $errors[] = "Unbekannter Mechanismus „{$mech}“ ({$tok}).";
                continue;
            }
            $value = $m[3] ?? '';
            $dual = ($m[4] ?? '') . ($m[5] ?? '');
            if (in_array($mech, ['include', 'exists'], true) && $value === '') {
                $errors[] = "Mechanismus $mech benötigt eine Domain ($tok).";
            }
            if ($mech === 'all' && ($value !== '' || $dual !== '')) {
                $errors[] = "all akzeptiert keine Parameter ($tok).";
            }
            $terms[] = [
                'kind' => 'mechanism', 'mechanism' => $mech, 'qualifier' => $m[1] ?: '+',
                'value' => rtrim($value . (in_array($mech, ['ip4', 'ip6'], true) ? $dual : ''), '.'),
                'cidr' => in_array($mech, ['ip4', 'ip6'], true) ? '' : $dual, 'raw' => $tok,
            ];
        }
        return ['terms' => $terms, 'errors' => $errors];
    }

    private function count(array &$node, array &$term): void
    {
        $this->lookups++;
        $node['lookups']++;
        $term['lookups'] = 1;
    }

    /** Ermittelt die effektive abschließende Policy (folgt redirect). */
    private function finalPolicy(array $node): ?array
    {
        if ($node['all'] !== null) {
            return ['qualifier' => $node['all'], 'domain' => $node['domain'], 'via_redirect' => false];
        }
        $r = $node['redirect'] ?? null;
        if ($r && !empty($r['children'])) {
            $p = $this->finalPolicy($r['children']);
            if ($p) {
                return ['via_redirect' => true] + $p;
            }
        }
        return null;
    }

    private function evaluatePolicy(?array $policy, array $root): void
    {
        if ($policy === null) {
            $this->add('warn', 'technical', 'spf.no_all', 'Der Record endet weder mit "all" noch mit redirect=. Nicht passende Absender erhalten das Ergebnis "neutral".', 'Die Policy ist faktisch offen.', 'Mit "-all" (oder zumindest "~all") abschließen.');
            return;
        }
        match ($policy['qualifier']) {
            '+' => $this->add('fail', 'technical', 'spf.plus_all', 'Der Record endet mit "+all": Jeder Server der Welt darf im Namen der Domain senden.', 'SPF bietet keinen Schutz.', 'Durch "-all" (oder "~all") ersetzen.'),
            '?' => $this->add('warn', 'technical', 'spf.neutral_all', 'Der Record endet mit "?all" (neutral): Es wird keine Aussage über unautorisierte Absender getroffen.', 'SPF hat keine Schutzwirkung.', 'Auf "~all" oder "-all" umstellen.'),
            '~' => $this->add('pass', 'bestpractice', 'spf.softfail_all', 'Der Record endet mit "~all" (SoftFail). Das ist verbreitet und wird in Kombination mit DMARC (p=quarantine/reject) praktisch durchgesetzt.', 'Unautorisierte Absender werden meist markiert, nicht zwingend abgelehnt.', 'Optional "-all", wenn alle legitimen Absender erfasst sind.'),
            default => $this->add('pass', 'technical', 'spf.hardfail_all', 'Der Record endet mit "-all" (HardFail): Nicht aufgeführte Server sind nicht autorisiert.', null, null),
        };
    }

    private function perm(string $code, string $message, string $recommendation): void
    {
        $this->permErrors[] = $message;
        $this->add('fail', 'technical', $code, $message, 'Empfänger werten SPF als PermError – SPF liefert keinen Schutz und kann Zustellprobleme verursachen.', $recommendation);
    }

    private function add(string $level, string $kind, string $code, string $message, ?string $impact, ?string $recommendation): void
    {
        foreach ($this->findings as $f) {
            if ($f['code'] === $code && $f['message'] === $message) {
                return;
            }
        }
        $this->findings[] = ['level' => $level, 'kind' => $kind, 'code' => $code, 'message' => $message, 'impact' => $impact, 'recommendation' => $recommendation];
    }

    /** @return array<int,array{label:string,value:string}> */
    private function describe(array $root): array
    {
        $ip4 = $ip6 = 0;
        $this->countIps($root, $ip4, $ip6);
        return [
            ['label' => 'DNS-Lookups (Limit ' . self::LOOKUP_LIMIT . ')', 'value' => (string) $this->lookups],
            ['label' => 'Void-Lookups (Limit ' . self::VOID_LIMIT . ')', 'value' => (string) $this->voids],
            ['label' => 'ip4-/ip6-Einträge', 'value' => "$ip4 / $ip6"],
            ['label' => 'PermError-Gründe', 'value' => (string) count($this->permErrors)],
        ];
    }

    private function countIps(array $node, int &$ip4, int &$ip6): void
    {
        foreach ($node['terms'] as $t) {
            if (($t['mechanism'] ?? '') === 'ip4') {
                $ip4++;
            } elseif (($t['mechanism'] ?? '') === 'ip6') {
                $ip6++;
            }
            if (!empty($t['children'])) {
                $this->countIps($t['children'], $ip4, $ip6);
            }
        }
    }

    /** @return array<string,mixed> */
    private function result(string $status, string $summary, ?string $record, array $details, ?array $policy): array
    {
        return [
            'id' => 'spf', 'title' => 'SPF', 'status' => $status, 'summary' => $summary, 'record' => $record,
            'findings' => $this->findings, 'details' => $details, 'policy' => $policy,
            'lookups' => $this->lookups, 'void_lookups' => $this->voids, 'perm_errors' => $this->permErrors,
            'truncated' => $this->truncated, 'dns_queries' => $this->dns->queries(),
        ];
    }
}

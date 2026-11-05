<?php
declare(strict_types=1);

namespace DomainScope\Services\DNSSEC;

use DomainScope\Services\DNS\DohClient;
use DomainScope\Services\DNS\RawDnsClient;
use DomainScope\Services\DNS\RecordFormatter;
use DomainScope\Services\Http\HostResolver;
use DomainScope\Validation\IpClassifier;
use DomainScope\Validation\PublicSuffix;

/**
 * DNSSEC- und Delegationsanalyse.
 *
 * Unterscheidet ausdrücklich drei Stufen:
 *  1. Records vorhanden (DS/DNSKEY/RRSIG/NSEC* ausgelesen)
 *  2. Konfiguration plausibel (DS passt per Digest zu einem DNSKEY, Signaturen zeitlich gültig, Algorithmen zulässig)
 *  3. Kryptografische Validierung – hier nur für das DNSKEY-RRset (RRSIG mit dem KSK geprüft). Die Kette bis zur
 *     Root und die Signaturen weiterer RRsets werden NICHT lokal geprüft; dafür dient das AD-Flag validierender Resolver.
 */
final class DnssecService
{
    public function __construct(
        private readonly DohClient $doh,
        private readonly RawDnsClient $raw = new RawDnsClient(),
        private readonly int $maxNameservers = 6,
    ) {
    }

    /** @return array<string,mixed> */
    public function analyze(string $zone, bool $directQueries = true): array
    {
        $started = microtime(true);
        $now = time();
        $resolvers = ['cloudflare', 'google'];
        $probe = 'dscope-' . substr(bin2hex(random_bytes(4)), 0, 7) . '.' . $zone;

        $reqs = [];
        foreach ($resolvers as $r) {
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'DS', 'opts' => ['do' => true]];
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'DNSKEY', 'opts' => ['do' => true]];
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'SOA', 'opts' => ['do' => true]];
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'NS', 'opts' => ['do' => true]];
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'NSEC3PARAM', 'opts' => ['do' => true]];
            $reqs[] = ['resolver' => $r, 'name' => $probe, 'type' => 'A', 'opts' => ['do' => true]];
            // Validierungsfehler-Test: gleiche Abfrage mit CD (Checking Disabled)
            $reqs[] = ['resolver' => $r, 'name' => $zone, 'type' => 'SOA', 'opts' => ['cd' => true]];
        }
        $res = $this->doh->queryMany($reqs);
        $per = [];
        foreach ($resolvers as $ri => $r) {
            $o = $ri * 7;
            $per[$r] = [
                'ds' => $res[$o], 'dnskey' => $res[$o + 1], 'soa' => $res[$o + 2], 'ns' => $res[$o + 3],
                'nsec3param' => $res[$o + 4], 'probe' => $res[$o + 5], 'soa_cd' => $res[$o + 6],
            ];
        }
        $primary = $this->firstUsable($per, 'dnskey') ?? 'cloudflare';

        // --- Rohdaten sammeln
        $dsRecords = $this->parseDs($per[$this->firstUsable($per, 'ds') ?? $primary]['ds']['answer'] ?? []);
        $dnskeyAns = $per[$primary]['dnskey']['answer'] ?? [];
        $dnskeys = $this->parseDnskeys($dnskeyAns);
        $rrsigs = $this->parseRrsigs($dnskeyAns, 'DNSKEY');

        $analysis = [
            'zone' => $zone, 'checked_at' => gmdate('Y-m-d H:i:s'),
            'ds' => [], 'dnskey' => [], 'rrsig' => [], 'denial' => null,
            'resolvers' => [], 'delegation' => null,
        ];

        // --- DNSKEY & Key-Tags
        foreach ($dnskeys as $k) {
            $rd = DnssecCrypto::dnskeyRdata($k['flags'], $k['protocol'], $k['algorithm'], $k['key']);
            $role = ($k['flags'] & 0x0001) ? 'KSK/SEP' : (($k['flags'] & 0x0100) ? 'ZSK' : 'Sonstig');
            $analysis['dnskey'][] = $k + [
                'keytag' => $rd !== null ? DnssecCrypto::keyTag($rd) : null, 'role' => $role,
                'algorithm_name' => DnssecCrypto::algorithmName($k['algorithm']),
                'strength' => DnssecCrypto::algorithmStrength($k['algorithm']),
                'bits' => $this->keyBits($k), 'rdata' => $rd,
            ];
        }

        // --- DS gegen DNSKEY (Digest-Vergleich)
        foreach ($dsRecords as $ds) {
            $match = null;
            foreach ($analysis['dnskey'] as $k) {
                if ($k['rdata'] === null || $k['keytag'] !== $ds['keytag'] || $k['algorithm'] !== $ds['algorithm']) {
                    continue;
                }
                $calc = DnssecCrypto::dsDigest($zone, $k['rdata'], $ds['digest_type']);
                if ($calc !== null && hash_equals($calc, $ds['digest'])) {
                    $match = $k;
                    break;
                }
            }
            $analysis['ds'][] = $ds + [
                'digest_type_name' => match ($ds['digest_type']) { 1 => 'SHA-1', 2 => 'SHA-256', 3 => 'GOST', 4 => 'SHA-384', default => 'Typ ' . $ds['digest_type'] },
                'algorithm_name' => DnssecCrypto::algorithmName($ds['algorithm']),
                'matches_dnskey' => $match !== null,
                'unverifiable' => !in_array($ds['digest_type'], [1, 2, 4], true),
            ];
        }

        // --- RRSIG des DNSKEY-RRsets: Zeitfenster + kryptografische Prüfung
        $cryptoVerified = null;
        foreach ($rrsigs as $sig) {
            $signerKey = null;
            foreach ($analysis['dnskey'] as $k) {
                if ($k['keytag'] === $sig['keytag'] && $k['algorithm'] === $sig['algorithm']) {
                    $signerKey = $k;
                    break;
                }
            }
            $entry = [
                'covered' => $sig['covered'], 'keytag' => $sig['keytag'], 'algorithm' => DnssecCrypto::algorithmName($sig['algorithm']),
                'signer' => $sig['signer'], 'inception' => $sig['inception'] ? gmdate('Y-m-d H:i:s', $sig['inception']) : null,
                'expiration' => $sig['expiration'] ? gmdate('Y-m-d H:i:s', $sig['expiration']) : null,
                'expired' => $sig['expiration'] !== null && $sig['expiration'] < $now,
                'not_yet_valid' => $sig['inception'] !== null && $sig['inception'] > $now,
                'hours_left' => $sig['expiration'] !== null ? (int) floor(($sig['expiration'] - $now) / 3600) : null,
                'signer_key_present' => $signerKey !== null,
                'signer_is_ksk' => $signerKey !== null && ($signerKey['flags'] & 1) === 1,
                'crypto' => null,
            ];
            if ($signerKey !== null) {
                $v = DnssecCrypto::verifyDnskeyRrset($zone, array_map(static fn($k) => [
                    'flags' => $k['flags'], 'protocol' => $k['protocol'], 'algorithm' => $k['algorithm'], 'key' => $k['key'],
                ], $analysis['dnskey']), $sig, $signerKey);
                $entry['crypto'] = $v;
                if ($v['valid'] === true && $entry['signer_is_ksk']) {
                    $cryptoVerified = ($cryptoVerified ?? true);
                } elseif ($v['valid'] === false) {
                    $cryptoVerified = false;
                }
            }
            $analysis['rrsig'][] = $entry;
        }

        // --- Denial of Existence (NSEC / NSEC3)
        $probeAns = $per[$primary]['probe'] ?? null;
        if ($probeAns && $probeAns['status'] !== 'timeout' && $probeAns['status'] !== 'error') {
            $types = array_unique(array_column($probeAns['authority'], 'type'));
            $nsec3 = array_values(array_filter($probeAns['authority'], static fn($r) => $r['type'] === 'NSEC3'));
            $params = $per[$primary]['nsec3param']['answer'][0]['data'] ?? null;
            $iter = null;
            if ($params && preg_match('/^\d+\s+\d+\s+(\d+)\s+/', $params, $m)) {
                $iter = (int) $m[1];
            } elseif ($nsec3 && preg_match('/^\d+\s+\d+\s+(\d+)\s+/', $nsec3[0]['data'], $m)) {
                $iter = (int) $m[1];
            }
            $analysis['denial'] = [
                'probe' => $probe, 'rcode' => $probeAns['rcode_name'],
                'mechanism' => in_array('NSEC3', $types, true) ? 'NSEC3' : (in_array('NSEC', $types, true) ? 'NSEC' : null),
                'nsec3param' => $params, 'nsec3_iterations' => $iter,
                'signed_denial' => in_array('RRSIG', $types, true),
            ];
        }

        // --- Resolver-Sicht (AD-Flag, Validierungsfehler)
        foreach ($resolvers as $r) {
            $normal = $per[$r]['soa'];
            $cd = $per[$r]['soa_cd'];
            $validationFailure = $normal['status'] === 'servfail' && in_array($cd['status'], ['ok'], true);
            $analysis['resolvers'][$r] = [
                'resolver' => $r,
                'ad' => (bool) ($normal['flags']['AD'] ?? false),
                'status' => $normal['status'], 'status_cd' => $cd['status'],
                'validation_failure' => $validationFailure,
                'usable' => !in_array($normal['status'], ['timeout', 'error'], true),
            ];
        }

        // --- Delegation (Parent/Child, direkte NS-Abfragen)
        if ($directQueries) {
            $analysis['delegation'] = $this->delegation($zone, $per, $primary);
        }

        // --- Gesamtbewertung
        $analysis += $this->conclude($analysis, $cryptoVerified);
        $analysis['duration_ms'] = (int) round((microtime(true) - $started) * 1000);
        $analysis['limitations'] = [
            'Kryptografisch geprüft werden DS↔DNSKEY (Digest) und die RRSIG des DNSKEY-RRsets (RSA, ECDSA P-256/P-384).',
            'Die Vertrauenskette bis zur Root-Zone und die Signaturen weiterer RRsets werden nicht lokal validiert; dafür wird das AD-Flag der Resolver Cloudflare/Google herangezogen (resolverabhängig).',
            'Die Parent-Zone wird anhand der Public-Suffix-Liste bestimmt; Zonen mit untypischen Delegationsgrenzen können abweichen.',
        ];
        return $analysis;
    }

    /** @return array<string,mixed> */
    private function delegation(string $zone, array $per, string $primary): array
    {
        $out = ['parent' => null, 'parent_ns' => [], 'parent_view' => null, 'child_ns' => [], 'servers' => [], 'issues' => [], 'soa_serials' => []];
        $parent = PublicSuffix::suffix($zone);
        if ($parent === $zone || !str_contains($zone, '.')) {
            $parent = substr($zone, (int) strpos($zone, '.') + 1);
        } else {
            $zoneLabels = explode('.', $zone);
            $parent = implode('.', array_slice($zoneLabels, 1));
        }
        $out['parent'] = $parent;
        $childNs = [];
        foreach ($per[$primary]['ns']['answer'] ?? [] as $r) {
            if ($r['type'] === 'NS') {
                $childNs[] = $r['data'];
            }
        }
        sort($childNs);
        $out['child_ns'] = $childNs;

        // Parent-NS ermitteln und einen davon direkt nach der Delegation fragen
        $parentNs = $this->doh->query($primary, $parent, 'NS');
        $parentHosts = array_values(array_map(static fn($r) => $r['data'], array_filter($parentNs['answer'], static fn($r) => $r['type'] === 'NS')));
        sort($parentHosts);
        $out['parent_ns'] = $parentHosts;
        foreach (array_slice($parentHosts, 0, 3) as $ph) {
            $ip = $this->publicIpOf($ph);
            if ($ip === null) {
                continue;
            }
            $ns = $this->raw->query($ip, $zone, 'NS', ['rd' => false, 'do' => true]);
            if (!$ns['ok']) {
                continue;
            }
            $delegated = [];
            $ds = [];
            foreach (array_merge($ns['authority'], $ns['answer']) as $r) {
                if ($r['type'] === 'NS' && $r['name'] === $zone) {
                    $delegated[] = $r['data'];
                }
                if ($r['type'] === 'DS' && $r['name'] === $zone) {
                    $ds[] = $r['data'];
                }
            }
            sort($delegated);
            $out['parent_view'] = [
                'server' => $ph, 'ip' => $ip, 'rcode' => $ns['rcode_name'], 'ns' => array_values(array_unique($delegated)),
                'ds' => $ds, 'via' => $ns['via'],
            ];
            break;
        }
        if ($out['parent_view'] !== null) {
            $pv = $out['parent_view']['ns'];
            if ($pv !== [] && $childNs !== [] && $pv !== array_values(array_unique($childNs))) {
                $out['issues'][] = [
                    'code' => 'delegation.ns_mismatch',
                    'message' => 'Die NS-Records im Parent (' . implode(', ', $pv) . ') weichen von denen der Zone selbst (' . implode(', ', $childNs) . ') ab.',
                ];
            }
        }

        // Jeden Child-NS direkt befragen: Erreichbarkeit, AA-Flag, SOA-Serial, DNSKEY
        $targets = $childNs !== [] ? $childNs : ($out['parent_view']['ns'] ?? []);
        foreach (array_slice($targets, 0, $this->maxNameservers) as $host) {
            $ip = $this->publicIpOf($host);
            $srv = ['host' => $host, 'ip' => $ip, 'reachable' => false, 'authoritative' => null, 'serial' => null, 'ms' => null, 'error' => null, 'dnskey_count' => null];
            if ($ip === null) {
                $srv['error'] = 'Nameserver-Name löst nicht auf eine öffentliche IP auf.';
                $out['issues'][] = ['code' => 'delegation.ns_unresolvable', 'message' => "Nameserver $host ist nicht auflösbar oder nicht öffentlich."];
                $out['servers'][] = $srv;
                continue;
            }
            $soa = $this->raw->query($ip, $zone, 'SOA', ['rd' => false, 'do' => false]);
            $srv['ms'] = $soa['ms'] ?? null;
            if (!$soa['ok']) {
                $srv['error'] = $soa['error'];
                $out['issues'][] = ['code' => 'delegation.ns_unreachable', 'message' => "Nameserver $host ($ip) antwortet nicht: " . $soa['error']];
                $out['servers'][] = $srv;
                continue;
            }
            $srv['reachable'] = true;
            $srv['authoritative'] = $soa['flags']['aa'];
            $srv['rcode'] = $soa['rcode_name'];
            foreach ($soa['answer'] as $r) {
                if ($r['type'] === 'SOA' && ($p = RecordFormatter::parseSoa($r['data'])) !== null) {
                    $srv['serial'] = $p['serial'];
                }
            }
            if (!$soa['flags']['aa'] || $soa['rcode'] !== 0 || $srv['serial'] === null) {
                $out['issues'][] = [
                    'code' => 'delegation.lame',
                    'message' => "Nameserver $host ($ip) ist für $zone nicht autoritativ (" . ($soa['flags']['aa'] ? '' : 'kein AA-Flag, ') . 'Antwortcode ' . $soa['rcode_name'] . ') – mögliche Lame Delegation.',
                ];
            }
            $key = $this->raw->query($ip, $zone, 'DNSKEY', ['rd' => false, 'do' => true]);
            if ($key['ok']) {
                $srv['dnskey_count'] = count(array_filter($key['answer'], static fn($r) => $r['type'] === 'DNSKEY'));
            }
            $out['servers'][] = $srv;
        }
        $serials = array_values(array_unique(array_filter(array_column($out['servers'], 'serial'), static fn($s) => $s !== null)));
        $out['soa_serials'] = $serials;
        if (count($serials) > 1) {
            $out['issues'][] = [
                'code' => 'delegation.serial_mismatch',
                'message' => 'Die Nameserver liefern unterschiedliche SOA-Serials (' . implode(', ', $serials) . '). Das kann ein kurzzeitiger Zonentransfer-Verzug oder dauerhaft inkonsistente Zonen bedeuten.',
            ];
        }
        $dnskeyCounts = array_values(array_unique(array_filter(array_column($out['servers'], 'dnskey_count'), static fn($c) => $c !== null)));
        if (count($dnskeyCounts) > 1) {
            $out['issues'][] = [
                'code' => 'delegation.dnskey_mismatch',
                'message' => 'Die Nameserver liefern unterschiedlich viele DNSKEYs (' . implode(' / ', $dnskeyCounts) . ') – bei DNSSEC-Multi-Signer-Setups oder Schlüsselwechseln relevant.',
            ];
        }
        if (count($childNs) === 1) {
            $out['issues'][] = ['code' => 'delegation.single_ns', 'message' => 'Die Zone hat nur einen Nameserver (keine Redundanz; Registries verlangen meist mindestens zwei).'];
        }
        return $out;
    }

    private function publicIpOf(string $host): ?string
    {
        $safe = HostResolver::resolveSafe($host);
        return $safe['ok'] ? $safe['ip'] : null;
    }

    /** @return array<string,mixed> */
    private function conclude(array $a, ?bool $cryptoVerified): array
    {
        $f = [];
        $add = static function (string $level, string $code, string $message, string $recommendation = '') use (&$f): void {
            $f[] = ['level' => $level, 'code' => $code, 'message' => $message, 'recommendation' => $recommendation];
        };
        $hasDs = $a['ds'] !== [];
        $hasKey = $a['dnskey'] !== [];
        $dsMatches = count(array_filter($a['ds'], static fn($d) => $d['matches_dnskey']));
        $adAny = false;
        $anyValidationFailure = false;
        foreach ($a['resolvers'] as $r) {
            $adAny = $adAny || $r['ad'];
            $anyValidationFailure = $anyValidationFailure || $r['validation_failure'];
        }
        $resolverUsable = count(array_filter($a['resolvers'], static fn($r) => $r['usable'])) > 0;

        if ($anyValidationFailure) {
            $state = 'broken';
            $add('fail', 'dnssec.validation_failure', 'Validierende Resolver liefern SERVFAIL, mit Checking Disabled (CD) aber eine Antwort: DNSSEC-Validierung schlägt fehl. Die Domain ist für Nutzer validierender Resolver nicht erreichbar.', 'DS-Record beim Registrar mit den aktuellen DNSKEYs abgleichen bzw. DNSSEC-Signierung der Zone reparieren (oder DS entfernen).');
        } elseif (!$hasDs && !$hasKey) {
            $state = 'unsigned';
            $add('info', 'dnssec.unsigned', 'Die Zone ist nicht mit DNSSEC signiert (weder DS im Parent noch DNSKEY in der Zone).', 'Optional DNSSEC beim DNS-Anbieter aktivieren und den DS-Record beim Registrar hinterlegen.');
        } elseif ($hasDs && !$hasKey) {
            $state = 'broken';
            $add('fail', 'dnssec.ds_without_dnskey', 'Im Parent existiert ein DS-Record, die Zone liefert aber keine DNSKEYs. Validierende Resolver werden die Domain als bogus ablehnen.', 'DS-Record beim Registrar entfernen oder DNSSEC beim DNS-Anbieter wieder aktivieren.');
        } elseif (!$hasDs && $hasKey) {
            $state = 'dnskey_only';
            $add('warn', 'dnssec.no_ds', 'Die Zone veröffentlicht DNSKEYs, im Parent ist aber kein DS-Record hinterlegt (unvollständige Vertrauenskette: "insecure delegation").', 'DS-Record beim Registrar eintragen, damit DNSSEC wirksam wird.');
        } elseif ($dsMatches === 0) {
            $unverifiable = count(array_filter($a['ds'], static fn($d) => $d['unverifiable'])) === count($a['ds']);
            $state = $unverifiable ? 'present' : 'broken';
            $add($unverifiable ? 'warn' : 'fail', 'dnssec.ds_mismatch', $unverifiable
                ? 'Die DS-Digest-Typen können lokal nicht berechnet werden; Übereinstimmung unbekannt.'
                : 'Kein DS-Record des Parents passt zu einem DNSKEY der Zone (Key-Tag/Algorithmus/Digest stimmen nicht überein). Die Vertrauenskette ist gebrochen.', 'Aktuellen KSK-Digest beim Registrar hinterlegen (DS-Update nach Schlüsselwechsel).');
        } else {
            $state = 'signed';
        }

        if ($anyValidationFailure && $hasDs && $hasKey && $dsMatches === 0) {
            $add('fail', 'dnssec.ds_mismatch', 'Kein DS-Record des Parents passt zu einem DNSKEY der Zone (Key-Tag/Algorithmus/Digest stimmen nicht überein). Die Vertrauenskette ist gebrochen.', 'Aktuellen KSK-Digest beim Registrar hinterlegen (DS-Update nach Schlüsselwechsel).');
        }
        foreach ($a['ds'] as $d) {
            if (!$d['matches_dnskey'] && $dsMatches > 0 && !$d['unverifiable']) {
                $add('warn', 'dnssec.ds_extra', "DS {$d['keytag']} ({$d['algorithm_name']}) hat keinen passenden DNSKEY (überzähliger/alter DS-Eintrag).", 'Veraltete DS-Records beim Registrar entfernen.');
            }
            if ($d['digest_type'] === 1) {
                $add('info', 'dnssec.ds_sha1', "DS {$d['keytag']} verwendet SHA-1 als Digest (veraltet).", 'Zusätzlich/ersatzweise SHA-256 (Typ 2) verwenden.');
            }
        }
        foreach ($a['dnskey'] as $k) {
            if ($k['strength'] === 'insecure') {
                $add('fail', 'dnssec.algorithm_insecure', "DNSKEY {$k['keytag']} nutzt den unsicheren Algorithmus {$k['algorithm_name']}.", 'Algorithmenwechsel auf 13 (ECDSA P-256) oder 8 (RSA-SHA256) planen.');
            } elseif ($k['strength'] === 'deprecated') {
                $add('warn', 'dnssec.algorithm_deprecated', "DNSKEY {$k['keytag']} nutzt den veralteten Algorithmus {$k['algorithm_name']}.", 'Algorithmenwechsel auf 13 oder 8 planen.');
            }
            if ($k['algorithm'] === 8 && $k['bits'] !== null && $k['bits'] < 2048 && ($k['flags'] & 1)) {
                $add('warn', 'dnssec.weak_ksk', "KSK {$k['keytag']} hat nur {$k['bits']} Bit.", 'Schlüssel mit ≥ 2048 Bit oder ECDSA verwenden.');
            }
        }
        foreach ($a['rrsig'] as $s) {
            if ($s['expired']) {
                $add('fail', 'dnssec.rrsig_expired', "Die RRSIG über das DNSKEY-RRset (Key-Tag {$s['keytag']}) ist am {$s['expiration']} UTC abgelaufen.", 'Zonensignierung prüfen (Signer-Dienst, automatische Re-Signierung).');
            } elseif ($s['not_yet_valid']) {
                $add('warn', 'dnssec.rrsig_not_yet_valid', "Die RRSIG (Key-Tag {$s['keytag']}) beginnt erst am {$s['inception']} UTC. Uhrzeit des Signers prüfen.", '');
            } elseif ($s['hours_left'] !== null && $s['hours_left'] < 48) {
                $add('warn', 'dnssec.rrsig_expiring', "Die RRSIG (Key-Tag {$s['keytag']}) läuft in {$s['hours_left']} Stunden ab.", 'Prüfen, ob die automatische Re-Signierung funktioniert.');
            }
            if ($s['crypto'] !== null && $s['crypto']['valid'] === false) {
                $add('fail', 'dnssec.rrsig_invalid', "Die kryptografische Prüfung der RRSIG über das DNSKEY-RRset (Key-Tag {$s['keytag']}) schlug fehl.", 'Zone neu signieren; Schlüsselmaterial und Signer prüfen.');
            }
        }
        if ($state === 'signed' && $a['rrsig'] === []) {
            $add('warn', 'dnssec.no_rrsig', 'Keine RRSIG zum DNSKEY-RRset erhalten (Resolver hat sie nicht geliefert oder Zone ist fehlerhaft signiert).', '');
        }
        if (($a['denial']['nsec3_iterations'] ?? 0) > 0) {
            $add('info', 'dnssec.nsec3_iterations', 'NSEC3 nutzt ' . $a['denial']['nsec3_iterations'] . ' zusätzliche Iterationen. RFC 9276 empfiehlt 0 Iterationen.', 'NSEC3-Parameter auf iterations=0 setzen.');
        }
        if ($state === 'signed' && $resolverUsable && !$adAny) {
            $add('warn', 'dnssec.no_ad', 'Kein befragter validierender Resolver setzt das AD-Flag, obwohl DS und DNSKEY konsistent erscheinen. (Hinweis: AD wird nur bei signierten Antworten gesetzt.)', 'Mit weiterem Resolver gegenprüfen (z. B. dnsviz.net).');
        }
        if ($a['delegation'] !== null) {
            foreach ($a['delegation']['issues'] as $iss) {
                $level = in_array($iss['code'], ['delegation.lame', 'delegation.ns_unreachable'], true) ? 'warn' : (str_contains($iss['code'], 'serial') || str_contains($iss['code'], 'ns_mismatch') ? 'warn' : 'info');
                $add($level, $iss['code'], $iss['message'], '');
            }
        }

        $validation = [
            'level' => match (true) {
                $state === 'unsigned' => 'none',
                $state === 'signed' && $cryptoVerified === true && $adAny => 'partial_local_plus_resolver',
                $state === 'signed' && $cryptoVerified === true => 'partial_local',
                $state === 'signed' && $adAny => 'resolver_only',
                default => 'records_only',
            },
            'ad_by' => array_keys(array_filter($a['resolvers'], static fn($r) => $r['ad'])),
            'local_dnskey_rrsig_verified' => $cryptoVerified,
        ];
        return ['state' => $state, 'validation' => $validation, 'findings' => $f];
    }

    private function firstUsable(array $per, string $key): ?string
    {
        foreach ($per as $r => $data) {
            if (!in_array($data[$key]['status'], ['timeout', 'error'], true)) {
                return $r;
            }
        }
        return null;
    }

    /** @return array<int,array{keytag:int,algorithm:int,digest_type:int,digest:string}> */
    private function parseDs(array $answers): array
    {
        $out = [];
        foreach ($answers as $r) {
            if ($r['type'] === 'DS' && ($p = RecordFormatter::parseDs($r['data'])) !== null) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /** @return array<int,array{flags:int,protocol:int,algorithm:int,key:string}> */
    private function parseDnskeys(array $answers): array
    {
        $out = [];
        foreach ($answers as $r) {
            if ($r['type'] === 'DNSKEY' && ($p = RecordFormatter::parseDnskey($r['data'])) !== null) {
                $out[] = $p;
            }
        }
        return $out;
    }

    /** @return array<int,array<string,mixed>> */
    private function parseRrsigs(array $answers, string $covered): array
    {
        $out = [];
        foreach ($answers as $r) {
            if ($r['type'] === 'RRSIG' && ($p = RecordFormatter::parseRrsig($r['data'])) !== null && $p['covered'] === $covered) {
                $out[] = $p;
            }
        }
        return $out;
    }

    private function keyBits(array $k): ?int
    {
        $raw = base64_decode($k['key'], true);
        if ($raw === false || $raw === '') {
            return null;
        }
        return match ($k['algorithm']) {
            5, 7, 8, 10 => (function () use ($raw): int {
                $explen = ord($raw[0]);
                $off = 1;
                if ($explen === 0) {
                    $explen = unpack('n', substr($raw, 1, 2))[1];
                    $off = 3;
                }
                $mod = ltrim(substr($raw, $off + $explen), "\x00");
                return strlen($mod) * 8;
            })(),
            13 => 256, 14 => 384, 15 => 256, 16 => 456,
            default => null,
        };
    }
}

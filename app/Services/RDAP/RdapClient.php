<?php
declare(strict_types=1);

namespace DomainScope\Services\RDAP;

use DomainScope\Services\Http\SafeHttp;

/**
 * RDAP-Client für Domains, IP-Adressen und AS-Nummern. Antworten werden als nicht vertrauenswürdig behandelt
 * und in ein festes, normalisiertes Format überführt.
 */
final class RdapClient
{
    /** @return array<string,mixed> */
    public function domain(string $domain): array
    {
        $tld = substr($domain, (int) strrpos($domain, '.') + 1);
        $base = RdapBootstrap::dnsService($tld);
        if ($base === null) {
            return $this->failure('unsupported_tld', "Für die TLD .$tld ist in den IANA-Bootstrap-Daten kein RDAP-Dienst eingetragen.");
        }
        $res = $this->fetch($base . 'domain/' . rawurlencode($domain), "rdap:$tld");
        if (!$res['ok']) {
            return $res + ['source_url' => $base];
        }
        $out = $this->normalizeDomain($res['json'], $res['url']);

        // Thin Registries (z. B. .com): Registrar-RDAP über "related"-Link ergänzen
        $related = $this->relatedLink($res['json']);
        if ($related !== null && $related !== $res['url']) {
            $second = $this->fetch($related, 'rdap:registrar');
            if ($second['ok']) {
                $detail = $this->normalizeDomain($second['json'], $second['url']);
                $out = $this->merge($out, $detail);
                $out['registrar_source_url'] = $second['url'];
            } else {
                $out['notes'][] = 'Registrar-RDAP nicht abrufbar: ' . ($second['error'] ?? 'unbekannt');
            }
        }
        return $out;
    }

    /** @return array<string,mixed> */
    public function ip(string $ip): array
    {
        $base = RdapBootstrap::ipService($ip);
        if ($base === null) {
            return $this->failure('unsupported', 'Kein RDAP-Dienst für diese IP-Adresse in den Bootstrap-Daten.');
        }
        $res = $this->fetch($base . 'ip/' . rawurlencode($ip), 'rdap:ip');
        if (!$res['ok']) {
            return $res;
        }
        $j = $res['json'];
        return [
            'ok' => true, 'source' => 'rdap', 'source_url' => $res['url'],
            'name' => $this->str($j['name'] ?? null), 'handle' => $this->str($j['handle'] ?? null),
            'country' => $this->str($j['country'] ?? null),
            'range' => trim(($j['startAddress'] ?? '') . ' – ' . ($j['endAddress'] ?? ''), ' –'),
            'cidr' => $this->cidr($j), 'type' => $this->str($j['type'] ?? null),
            'parent' => $this->str($j['parentHandle'] ?? null),
            'registrant' => $this->entityNames($j['entities'] ?? [], ['registrant', 'administrative', 'technical', 'abuse']),
            'events' => $this->events($j['events'] ?? []),
            'status' => array_map('strval', (array) ($j['status'] ?? [])),
            'fetched_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    /** @return array<string,mixed> */
    public function asn(int $asn): array
    {
        $base = RdapBootstrap::asnService($asn);
        if ($base === null) {
            return $this->failure('unsupported', 'Kein RDAP-Dienst für diese AS-Nummer.');
        }
        $res = $this->fetch($base . 'autnum/' . $asn, 'rdap:asn');
        if (!$res['ok']) {
            return $res;
        }
        $j = $res['json'];
        return [
            'ok' => true, 'source' => 'rdap', 'source_url' => $res['url'], 'name' => $this->str($j['name'] ?? null),
            'handle' => $this->str($j['handle'] ?? null), 'country' => $this->str($j['country'] ?? null),
            'events' => $this->events($j['events'] ?? []), 'fetched_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    /** @return array{ok:bool,json?:array,url?:string,error?:string,error_code?:string,http?:int} */
    private function fetch(string $url, string $source): array
    {
        $res = SafeHttp::request($url, [
            'headers' => ['Accept: application/rdap+json, application/json'],
            'timeout' => 15, 'max_bytes' => 1_500_000, 'source' => $source, 'label' => 'RDAP (' . substr($source, 5) . ')',
        ]);
        if ($res['error_code'] !== null) {
            return $this->failure($res['error_code'] === 'timeout' ? 'timeout' : 'unreachable', 'RDAP-Server nicht erreichbar: ' . $res['error']);
        }
        if ($res['status'] === 404) {
            return $this->failure('not_found', 'Der RDAP-Server kennt dieses Objekt nicht (404). Die Domain ist möglicherweise nicht registriert.') + ['http' => 404];
        }
        if ($res['status'] === 429) {
            $retry = $res['headers']['retry-after'] ?? null;
            return $this->failure('rate_limited', 'Rate-Limit des RDAP-Servers erreicht (429).' . ($retry ? " Retry-After: $retry" : '')) + ['http' => 429];
        }
        if ($res['status'] < 200 || $res['status'] >= 300) {
            return $this->failure('http_error', 'RDAP-Server antwortete mit HTTP ' . $res['status'] . '.') + ['http' => $res['status']];
        }
        $json = json_decode($res['body'], true);
        if (!is_array($json)) {
            return $this->failure('invalid_response', 'Die RDAP-Antwort ist kein gültiges JSON.');
        }
        return ['ok' => true, 'json' => $json, 'url' => $res['final_url']];
    }

    private function failure(string $code, string $message): array
    {
        return ['ok' => false, 'source' => 'rdap', 'error_code' => $code, 'error' => $message, 'fetched_at' => gmdate('Y-m-d H:i:s')];
    }

    /** @return array<string,mixed> */
    public function normalizeDomain(array $j, string $url): array
    {
        $events = $this->events($j['events'] ?? []);
        $byAction = [];
        foreach ($events as $ev) {
            $byAction[$ev['action']] ??= $ev['date'];
        }
        $ns = [];
        foreach ((array) ($j['nameservers'] ?? []) as $n) {
            if (is_array($n) && !empty($n['ldhName'])) {
                $ns[] = rtrim(strtolower((string) $n['ldhName']), '.');
            }
        }
        sort($ns);
        $secure = $j['secureDNS'] ?? null;
        $signed = is_array($secure) && array_key_exists('delegationSigned', $secure) ? (bool) $secure['delegationSigned'] : null;
        $registrar = null;
        $iana = null;
        $entities = [];
        foreach ((array) ($j['entities'] ?? []) as $ent) {
            if (!is_array($ent)) {
                continue;
            }
            $roles = array_map('strval', (array) ($ent['roles'] ?? []));
            $name = $this->vcardValue($ent, 'fn') ?? $this->vcardValue($ent, 'org');
            $redacted = $name === null || preg_match('/redact|privacy|withheld|data protected/i', (string) $name) === 1;
            $entities[] = ['roles' => $roles, 'name' => $name, 'handle' => $this->str($ent['handle'] ?? null), 'redacted' => $redacted];
            if (in_array('registrar', $roles, true)) {
                $registrar ??= $name;
                foreach ((array) ($ent['publicIds'] ?? []) as $pid) {
                    if (($pid['type'] ?? '') === 'IANA Registrar ID') {
                        $iana = (string) $pid['identifier'];
                    }
                }
                // Abuse-Kontakt
                foreach ((array) ($ent['entities'] ?? []) as $sub) {
                    if (is_array($sub) && in_array('abuse', (array) ($sub['roles'] ?? []), true)) {
                        $entities[] = ['roles' => ['abuse'], 'name' => $this->vcardValue($sub, 'fn'), 'email' => $this->vcardValue($sub, 'email'), 'handle' => null, 'redacted' => false];
                    }
                }
            }
        }
        $dsData = [];
        foreach ((array) ($secure['dsData'] ?? []) as $ds) {
            if (is_array($ds)) {
                $dsData[] = trim(($ds['keyTag'] ?? '') . ' ' . ($ds['algorithm'] ?? '') . ' ' . ($ds['digestType'] ?? '') . ' ' . ($ds['digest'] ?? ''));
            }
        }
        return [
            'ok' => true, 'source' => 'rdap', 'source_url' => $url,
            'domain' => $this->str($j['ldhName'] ?? null),
            'handle' => $this->str($j['handle'] ?? null),
            'registrar' => $registrar, 'registrar_iana_id' => $iana,
            'registered_at' => $this->date($byAction['registration'] ?? null),
            'changed_at' => $this->date($byAction['last changed'] ?? null),
            'expires_at' => $this->date($byAction['expiration'] ?? null),
            'statuses' => array_values(array_map('strval', (array) ($j['status'] ?? []))),
            'nameservers' => $ns,
            'dnssec_signed' => $signed, 'ds_data' => $dsData,
            'events' => $events, 'entities' => $entities,
            'notes' => $this->remarks($j),
            'fetched_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    /** Vereint Registry-Daten (Basis) mit detaillierteren Registrar-Daten. */
    private function merge(array $registry, array $registrar): array
    {
        foreach (['registrar', 'registrar_iana_id', 'registered_at', 'changed_at', 'expires_at', 'dnssec_signed'] as $k) {
            if (($registry[$k] ?? null) === null && ($registrar[$k] ?? null) !== null) {
                $registry[$k] = $registrar[$k];
            }
        }
        if (($registrar['expires_at'] ?? null) !== null) {
            // Der Registrar kennt das Ablaufdatum aktuell; Registry-Wert ist maßgeblich nur wenn vorhanden
            $registry['expires_at'] ??= $registrar['expires_at'];
        }
        $registry['statuses'] = array_values(array_unique(array_merge($registry['statuses'], $registrar['statuses'])));
        if ($registry['nameservers'] === []) {
            $registry['nameservers'] = $registrar['nameservers'];
        }
        $registry['entities'] = array_merge($registry['entities'], $registrar['entities']);
        $registry['events'] = array_merge($registry['events'], array_map(static fn($e) => $e + ['from' => 'registrar'], $registrar['events']));
        $registry['notes'] = array_values(array_unique(array_merge($registry['notes'] ?? [], $registrar['notes'] ?? [])));
        return $registry;
    }

    private function relatedLink(array $j): ?string
    {
        foreach ((array) ($j['links'] ?? []) as $link) {
            if (is_array($link) && ($link['rel'] ?? '') === 'related' && !empty($link['href'])
                && str_contains((string) ($link['type'] ?? 'application/rdap+json'), 'rdap')) {
                return (string) $link['href'];
            }
        }
        return null;
    }

    /** @return array<int,array{action:string,date:string}> */
    private function events(array $events): array
    {
        $out = [];
        foreach ($events as $e) {
            if (is_array($e) && isset($e['eventAction'], $e['eventDate'])) {
                $d = $this->date((string) $e['eventDate']);
                if ($d !== null) {
                    $out[] = ['action' => strtolower((string) $e['eventAction']), 'date' => $d];
                }
            }
        }
        return $out;
    }

    private function date(?string $iso): ?string
    {
        if ($iso === null || $iso === '') {
            return null;
        }
        try {
            return (new \DateTimeImmutable($iso))->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s');
        } catch (\Throwable) {
            return null;
        }
    }

    private function vcardValue(array $entity, string $field): ?string
    {
        foreach ((array) ($entity['vcardArray'][1] ?? []) as $item) {
            if (is_array($item) && ($item[0] ?? '') === $field && isset($item[3])) {
                $v = $item[3];
                $v = is_array($v) ? implode(' ', array_filter(array_map('strval', $v))) : (string) $v;
                $v = trim($v);
                return $v === '' ? null : mb_substr($v, 0, 255);
            }
        }
        return null;
    }

    /** @return string[] */
    private function remarks(array $j): array
    {
        $out = [];
        foreach ((array) ($j['remarks'] ?? []) as $r) {
            if (is_array($r) && !empty($r['description'])) {
                $out[] = mb_substr(implode(' ', array_map('strval', (array) $r['description'])), 0, 300);
            }
        }
        foreach ((array) ($j['notices'] ?? []) as $r) {
            if (is_array($r) && !empty($r['title']) && preg_match('/redact|status|terms/i', (string) $r['title'])) {
                $out[] = mb_substr((string) $r['title'], 0, 200);
            }
        }
        return array_slice($out, 0, 6);
    }

    /** @return string[] */
    private function entityNames(array $entities, array $roles): array
    {
        $out = [];
        foreach ($entities as $ent) {
            if (is_array($ent) && array_intersect($roles, (array) ($ent['roles'] ?? []))) {
                $n = $this->vcardValue($ent, 'fn') ?? $this->vcardValue($ent, 'org');
                if ($n !== null) {
                    $out[] = $n;
                }
            }
        }
        return array_values(array_unique($out));
    }

    private function cidr(array $j): ?string
    {
        foreach ((array) ($j['cidr0_cidrs'] ?? []) as $c) {
            if (isset($c['v4prefix'])) {
                return $c['v4prefix'] . '/' . $c['length'];
            }
            if (isset($c['v6prefix'])) {
                return $c['v6prefix'] . '/' . $c['length'];
            }
        }
        return null;
    }

    private function str(mixed $v): ?string
    {
        return is_scalar($v) && (string) $v !== '' ? mb_substr((string) $v, 0, 255) : null;
    }
}

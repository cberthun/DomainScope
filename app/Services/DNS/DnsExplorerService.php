<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

use DomainScope\Support\Config;
use DomainScope\Validation\IpClassifier;

/** Mehrfach-Lookups über mehrere Resolver, Vergleich, Export. */
final class DnsExplorerService
{
    public function __construct(private readonly DohClient $doh)
    {
    }

    /**
     * @param string[] $types
     * @param string[] $resolvers
     * @param array{do?:bool,cd?:bool,fresh?:bool} $opts
     * @return array<string,mixed>
     */
    public function lookup(string $name, array $types, array $resolvers, array $opts = []): array
    {
        $available = array_keys((array) Config::get('app.dns.resolvers'));
        $resolvers = array_values(array_intersect($resolvers, $available)) ?: [(string) Config::get('app.dns.default_resolver')];
        $types = array_values(array_unique(array_filter(array_map('strtoupper', $types), static fn($t) => DnsTypes::code($t) !== null)));
        if ($types === []) {
            $types = ['A'];
        }
        $name = rtrim(strtolower($name), '.');
        $queryName = $name;
        $note = null;
        if (IpClassifier::isValid($name)) {
            $queryName = (string) IpClassifier::reverseName($name);
            $types = ['PTR'];
            $note = 'IP-Adresse erkannt: Reverse-Lookup über ' . $queryName;
        }

        $reqs = [];
        $index = [];
        foreach ($resolvers as $r) {
            foreach ($types as $t) {
                $reqs[] = ['resolver' => $r, 'name' => $queryName, 'type' => $t, 'opts' => $opts];
                $index[] = [$r, $t];
            }
        }
        $res = $this->doh->queryMany($reqs);
        $results = [];
        foreach ($res as $i => $r) {
            [$resolver, $type] = $index[$i];
            $results[$resolver][$type] = $r;
        }
        return [
            'name' => $name, 'query_name' => $queryName, 'types' => $types, 'resolvers' => $resolvers, 'results' => $results,
            'comparison' => count($resolvers) > 1 ? $this->compare($results, $types, $resolvers) : [],
            'note' => $note, 'checked_at' => gmdate('Y-m-d H:i:s'),
        ];
    }

    /**
     * Vergleicht je Typ die Datensätze zweier oder mehrerer Resolver (TTL wird ignoriert).
     *
     * @return array<string,array{consistent:bool,comparable:bool,only:array<string,string[]>,resolvers:string[]}>
     */
    public function compare(array $results, array $types, array $resolvers): array
    {
        $out = [];
        foreach ($types as $t) {
            $sets = [];
            foreach ($resolvers as $r) {
                $res = $results[$r][$t] ?? null;
                if ($res === null || in_array($res['status'], ['timeout', 'error', 'servfail', 'refused'], true)) {
                    continue;
                }
                $sets[$r] = array_values(array_unique(array_map(
                    static fn($x) => $x['data'],
                    array_filter($res['answer'], static fn($x) => $x['type'] === $t)
                )));
                sort($sets[$r]);
            }
            $union = array_unique(array_merge(...array_values($sets) ?: [[]]));
            $only = [];
            foreach ($sets as $r => $s) {
                $only[$r] = array_values(array_diff($union, $s));
            }
            $consistent = true;
            foreach ($only as $missing) {
                if ($missing) {
                    $consistent = false;
                }
            }
            $out[$t] = ['consistent' => $consistent, 'comparable' => count($sets) > 1, 'missing_in' => $only, 'resolvers' => array_keys($sets), 'sets' => $sets];
        }
        return $out;
    }

    /**
     * Konsistenzprüfung zwischen Cloudflare und Google für Monitoring/Findings.
     *
     * @return array<string,array<string,mixed>> nur abweichende Typen
     */
    public function consistency(string $name): array
    {
        $types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'];
        $data = $this->lookup($name, $types, ['cloudflare', 'google']);
        $diffs = [];
        foreach ($data['comparison'] as $type => $c) {
            if ($c['comparable'] && !$c['consistent']) {
                $sets = $c['sets'];
                $diffs[$type] = [
                    'resolvers' => ['cloudflare', 'google'],
                    'only_a' => array_values(array_diff($sets['cloudflare'] ?? [], $sets['google'] ?? [])),
                    'only_b' => array_values(array_diff($sets['google'] ?? [], $sets['cloudflare'] ?? [])),
                ];
            }
        }
        return ['diffs' => $diffs, 'lookup' => $data];
    }

    /**
     * Flache Records-Liste (für Tabellen und Exporte).
     *
     * @return array<int,array<string,mixed>>
     */
    public static function flatten(array $lookup): array
    {
        $rows = [];
        foreach ($lookup['results'] as $resolver => $byType) {
            foreach ($byType as $type => $r) {
                foreach (['answer' => 'Answer', 'authority' => 'Authority', 'additional' => 'Additional'] as $key => $section) {
                    foreach ($r[$key] as $rec) {
                        $rows[] = [
                            'resolver' => $resolver, 'query_type' => $type, 'section' => $section, 'name' => $rec['name'],
                            'type' => $rec['type'], 'ttl' => $rec['ttl'], 'data' => $rec['data'], 'rcode' => $r['rcode_name'], 'ms' => $r['ms'],
                        ];
                    }
                }
            }
        }
        return $rows;
    }

    /** CSV-Export mit Schutz vor Formel-Injektion (CSV-Injection). */
    public static function toCsv(array $rows, array $columns): string
    {
        $fh = fopen('php://temp', 'r+');
        fwrite($fh, "\xEF\xBB\xBF");
        fputcsv($fh, $columns, ',', '"', '\\');
        foreach ($rows as $row) {
            $line = [];
            foreach ($columns as $c) {
                $v = (string) ($row[$c] ?? '');
                if ($v !== '' && in_array($v[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
                    $v = "'" . $v;
                }
                $line[] = $v;
            }
            fputcsv($fh, $line, ',', '"', '\\');
        }
        rewind($fh);
        return (string) stream_get_contents($fh);
    }
}

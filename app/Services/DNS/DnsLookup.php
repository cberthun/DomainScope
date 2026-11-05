<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

use DomainScope\Support\Config;

/**
 * Bequeme, budgetierte Abfrage-Schicht für Analysemodule (SPF, DMARC, DNSSEC …).
 * Nutzt einen primären Resolver; bei Resolver-Ausfall (Timeout/Fehler) wird einmal auf den nächsten ausgewichen.
 */
final class DnsLookup
{
    private int $count = 0;
    /** @var string[] */
    private array $order;

    public function __construct(private readonly DohClient $doh, ?string $primary = null, private readonly int $budget = 80)
    {
        $primary ??= (string) Config::get('app.dns.default_resolver', 'cloudflare');
        $all = array_keys((array) Config::get('app.dns.resolvers'));
        $this->order = array_values(array_unique([$primary, ...$all]));
    }

    public function queries(): int
    {
        return $this->count;
    }

    public function budgetExhausted(): bool
    {
        return $this->count >= $this->budget;
    }

    public function client(): DohClient
    {
        return $this->doh;
    }

    /** @param array{do?:bool,cd?:bool,fresh?:bool} $opts */
    public function get(string $name, string $type, array $opts = []): array
    {
        $last = null;
        foreach (array_slice($this->order, 0, 2) as $resolver) {
            if ($this->count >= $this->budget) {
                return [
                    'resolver' => $resolver, 'name' => $name, 'type' => $type, 'status' => 'error', 'answer' => [],
                    'authority' => [], 'additional' => [], 'flags' => [], 'ms' => 0, 'rcode' => null, 'rcode_name' => null,
                    'error' => 'Abfrage-Budget erschöpft', 'explanation' => 'Das Limit an DNS-Abfragen dieser Analyse wurde erreicht.',
                ];
            }
            $this->count++;
            $last = $this->doh->query($resolver, $name, $type, $opts);
            if (!in_array($last['status'], ['timeout', 'error'], true)) {
                return $last;
            }
        }
        return $last;
    }

    /**
     * Liefert die Daten aller Records des Typs.
     *
     * @return array{status:string,values:string[],records:array,error:?string}
     */
    public function values(string $name, string $type, array $opts = []): array
    {
        $r = $this->get($name, $type, $opts);
        $recs = array_values(array_filter($r['answer'], static fn($x) => $x['type'] === strtoupper($type)));
        return [
            'status' => $r['status'], 'values' => array_map(static fn($x) => $x['data'], $recs),
            'records' => $recs, 'error' => $r['error'] ?? null, 'result' => $r,
        ];
    }

    /** TXT-Records, die mit einem Präfix beginnen (z. B. "v=spf1"). */
    public function txtWithPrefix(string $name, string $prefix): array
    {
        $r = $this->values($name, 'TXT');
        $r['values'] = array_values(array_filter(
            $r['values'],
            static fn($v) => stripos(ltrim($v), $prefix) === 0
        ));
        return $r;
    }

    /** @return array{ok:bool,hosts:string[]} Hinweis: erreichbar wenn A oder AAAA existiert */
    public function addresses(string $name): array
    {
        $a = $this->values($name, 'A');
        $aaaa = $this->values($name, 'AAAA');
        return [
            'a' => $a['values'], 'aaaa' => $aaaa['values'],
            'status_a' => $a['status'], 'status_aaaa' => $aaaa['status'],
            'cname_only' => false,
        ];
    }
}

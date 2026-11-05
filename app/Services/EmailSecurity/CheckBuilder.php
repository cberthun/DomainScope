<?php
declare(strict_types=1);

namespace DomainScope\Services\EmailSecurity;

/** Gemeinsame Hilfen zum Aufbau einheitlicher Prüfergebnisse. */
trait CheckBuilder
{
    /** @var array<int,array<string,mixed>> */
    private array $findings = [];

    private function reset(): void
    {
        $this->findings = [];
    }

    private function add(string $level, string $kind, string $code, string $message, ?string $impact = null, ?string $recommendation = null): void
    {
        $this->findings[] = compact('level', 'kind', 'code', 'message', 'impact', 'recommendation');
    }

    private function statusFromFindings(): string
    {
        $status = 'pass';
        foreach ($this->findings as $f) {
            if ($f['level'] === 'fail') {
                return 'fail';
            }
            if ($f['level'] === 'warn') {
                $status = 'warn';
            }
        }
        return $status;
    }

    /** @return array<string,mixed> */
    private function build(string $id, string $title, string $status, string $summary, ?string $record, array $details = [], array $extra = []): array
    {
        return [
            'id' => $id, 'title' => $title, 'status' => $status, 'summary' => $summary, 'record' => $record,
            'findings' => $this->findings, 'details' => $details,
        ] + $extra;
    }

    /** Parst "tag=value; tag=value" (DMARC, DKIM, BIMI, TLS-RPT). @return array<string,string> */
    private function tags(string $record): array
    {
        $out = [];
        foreach (explode(';', $record) as $part) {
            $part = trim($part);
            if ($part === '' || !str_contains($part, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $part, 2);
            $k = strtolower(trim($k));
            if (!isset($out[$k])) {
                $out[$k] = trim($v);
            }
        }
        return $out;
    }
}

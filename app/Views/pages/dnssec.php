<?php
/**
 * @var array $domains
 * @var array $results
 * @var int $staleHours
 */
echo \DomainScope\Support\View::partial('partials/domain_picker', ['action' => '/dnssec', 'label' => 'DNSSEC prüfen']);
$labels = ['signed' => 'signiert', 'unsigned' => 'nicht signiert', 'broken' => 'defekt', 'dnskey_only' => 'DNSKEY ohne DS', 'present' => 'vorhanden'];
?>
<section class="card">
    <header class="card-header"><h2>DNSSEC-Status gespeicherter Domains</h2></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('shield-check', 'Noch keine Domains', 'Geprüft werden DS, DNSKEY, RRSIG, NSEC/NSEC3 und die Delegation mit direkten Abfragen der autoritativen Nameserver.') ?>
        <?php else: ?>
            <?= ui_table_open('dnssec-table', ['Domain', 'Zustand', 'Validierung', 'Befunde', 'Geprüft']) ?>
            <?php foreach ($domains as $d): $res = $results[(int) $d['id']] ?? null; $a = $res['data'] ?? null; ?>
                <tr><td><a class="mono" href="/dnssec/<?= e(rawurlencode($d['name'])) ?>"><?= e($d['unicode_name']) ?></a></td>
                    <td><?= $a ? ui_pill($res['status'], $labels[$a['state']] ?? $a['state']) : '<span class="muted">nicht geprüft</span>' ?></td>
                    <td class="small"><?= $a ? e(match ($a['validation']['level']) { 'none' => '–', 'records_only' => 'nur Records', 'resolver_only' => 'Resolver (AD)', 'partial_local' => 'lokal teilweise', 'partial_local_plus_resolver' => 'lokal teilweise + Resolver', default => '' }) : '' ?></td>
                    <td class="small"><?= $a ? count(array_filter($a['findings'], static fn($f) => in_array($f['level'], ['fail', 'warn'], true))) : '–' ?></td>
                    <td><?= $res ? ui_freshness($res['checked_at'], $staleHours) : '<span class="muted">nie</span>' ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>

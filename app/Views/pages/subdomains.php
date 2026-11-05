<?php
/**
 * @var array $domains
 * @var array $stats
 * @var array $scan
 * @var int $staleHours
 */
echo \DomainScope\Support\View::partial('partials/domain_picker', ['action' => '/subdomains', 'label' => 'Subdomains anzeigen']);
?>
<section class="card">
    <header class="card-header"><h2>Domains</h2></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('git-branch', 'Noch keine Domains', 'Passive Erkennung über Certificate-Transparency-Logs, ohne aktive Verbindungen zur Zieldomain.') ?>
        <?php else: ?>
            <?= ui_table_open('subs-overview', ['Domain', 'Subdomains', 'Nicht mehr gefunden', 'Letzter Scan', 'Neu im letzten Scan']) ?>
            <?php foreach ($domains as $d): $s = $stats[(int) $d['id']] ?? null; $sc = $scan[(int) $d['id']] ?? null; ?>
                <tr><td><a class="mono" href="/subdomains/<?= e(rawurlencode($d['name'])) ?>"><?= e($d['unicode_name']) ?></a></td>
                    <td class="num"><?= $s ? (int) $s['present'] : '–' ?></td><td class="num"><?= $s ? (int) $s['missing'] : '–' ?></td>
                    <td><?= $sc ? ui_freshness($sc['scanned_at'], $staleHours * 7) : '<span class="muted">nie</span>' ?></td>
                    <td class="num"><?= $sc ? (int) $sc['new_count'] : '–' ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>

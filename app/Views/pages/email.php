<?php
/**
 * @var array $domains
 * @var array $results
 * @var int $staleHours
 */
echo \DomainScope\Support\View::partial('partials/domain_picker', ['action' => '/email', 'label' => 'E-Mail-Sicherheit prüfen']);
?>
<section class="card">
    <header class="card-header"><h2>Übersicht gespeicherter Domains</h2></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('mail', 'Noch keine Domains', 'Eine Domain oben eingeben – SPF, DKIM, DMARC, MX/PTR, MTA-STS, TLS-RPT und BIMI werden live geprüft.') ?>
        <?php else:
            $ids = ['spf' => 'SPF', 'dkim' => 'DKIM', 'dmarc' => 'DMARC', 'mx' => 'MX/PTR', 'mta-sts' => 'MTA-STS', 'tls-rpt' => 'TLS-RPT', 'bimi' => 'BIMI']; ?>
            <?= ui_table_open('email-table', array_merge(['Domain'], array_values($ids), ['Geprüft'])) ?>
            <?php foreach ($domains as $d): $res = $results[(int) $d['id']] ?? null; ?>
                <tr><td><a class="mono" href="/email/<?= e(rawurlencode($d['name'])) ?>"><?= e($d['unicode_name']) ?></a></td>
                    <?php foreach (array_keys($ids) as $k): ?>
                        <td><?= $res ? ui_pill($res['data']['checks'][$k]['status'] ?? 'unknown') : '<span class="muted">–</span>' ?></td>
                    <?php endforeach; ?>
                    <td><?= $res ? ui_freshness($res['checked_at'], $staleHours) : '<span class="muted">nie</span>' ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>

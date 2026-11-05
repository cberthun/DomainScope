<?php
/**
 * @var array $domain
 * @var array $ips
 */
?>
<div class="toolbar">
    <?= ui_run_button($domain, 'ips', 'IP-Daten anreichern', ['force' => '1'], 'btn btn-primary btn-sm') ?>
</div>
<section class="card">
    <div class="card-body flush">
        <?php if (!$ips): ?>
            <?= ui_empty('server', 'Noch keine IP-Zuordnungen', 'IP-Adressen entstehen aus A/AAAA-Records (DNS-Snapshot) und aufgelösten Subdomains.') ?>
        <?php else: ?>
            <?= ui_table_open('ip-table', ['Hostname', 'Typ', 'IP-Adresse', 'ASN / Netzwerk', 'Präfix', 'Reverse-DNS', 'Geprüft']) ?>
            <?php foreach ($ips as $ip): ?>
                <tr>
                    <td class="mono small"><?= e($ip['hostname']) ?></td>
                    <td><span class="badge badge-type"><?= e($ip['record_type']) ?></span></td>
                    <td><a class="mono" href="/ip/<?= e(rawurlencode($ip['address'])) ?>"><?= e($ip['address']) ?></a></td>
                    <td class="small"><?= $ip['asn'] ? 'AS' . (int) $ip['asn'] . ' · ' . e($ip['as_name'] ?? '') : '<span class="muted">nicht ermittelt</span>' ?></td>
                    <td class="mono small"><?= e($ip['prefix'] ?? '–') ?></td>
                    <td class="mono small"><?= e($ip['reverse_dns'] ?? '–') ?></td>
                    <td class="small"><?= $ip['checked_at'] ? e(time_ago($ip['checked_at'])) : '–' ?></td>
                </tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>

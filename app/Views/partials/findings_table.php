<?php
/**
 * @var array $findings
 * @var bool $showDomain
 */
$showDomain ??= true;
if (!$findings) {
    echo ui_empty('circle-check', 'Keine Findings', 'Für diese Auswahl liegen keine Findings vor. Findings entstehen ausschließlich aus Prüfergebnissen.');
    return;
}
$cols = ['Schweregrad', 'Titel', ...($showDomain ? ['Domain'] : []), 'Kategorie', 'Status', 'Zuletzt gesehen'];
echo ui_table_open('findings-table', $cols);
foreach ($findings as $f): ?>
    <tr>
        <td data-sort-value="<?= (int) array_search($f['severity'], ['critical', 'high', 'medium', 'low', 'unknown', 'info'], true) ?>"><?= sev_badge($f['severity']) ?></td>
        <td><a href="/findings/<?= (int) $f['id'] ?>"><?= e($f['title']) ?></a><?= $f['subject'] ? ' <span class="muted small mono">' . e($f['subject']) . '</span>' : '' ?></td>
        <?php if ($showDomain): ?><td><?= $f['domain_name'] ? ui_domain_link($f['domain_name']) : '–' ?></td><?php endif; ?>
        <td class="small"><?= e($f['category']) ?></td>
        <td><?= match ($f['status']) { 'open' => badge('offen', 'warn'), 'acknowledged' => badge('bestätigt', 'info'), 'ignored' => badge('ignoriert', 'neutral'), default => badge('behoben', 'ok') } ?></td>
        <td data-sort-value="<?= e($f['last_seen']) ?>" class="small"><?= e(time_ago($f['last_seen'])) ?></td>
    </tr>
<?php endforeach;
echo ui_table_close();

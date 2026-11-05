<?php
/**
 * @var array $a
 * @var array $b
 * @var array $diff
 * @var bool $same
 * @var array $records
 */
?>
<section class="card">
    <div class="card-body">
        <?= ui_kv([
            ['Domain', ui_domain_link($a['domain_name'])],
            ['Snapshot A', '<span class="mono">#' . (int) $a['id'] . '</span> · ' . e($a['host']) . ' · ' . e(fmt_dt($a['taken_at'], 'd.m.Y H:i:s')) . ' ' . tz_label() . ' · ' . (int) $a['record_count'] . ' Records'],
            ['Snapshot B', '<span class="mono">#' . (int) $b['id'] . '</span> · ' . e($b['host']) . ' · ' . e(fmt_dt($b['taken_at'], 'd.m.Y H:i:s')) . ' ' . tz_label() . ' · ' . (int) $b['record_count'] . ' Records'],
        ], 'kv-compact') ?>
        <?php if ($a['host'] !== $b['host']): ?><div class="alert alert-warn small">Die Snapshots gehören zu unterschiedlichen Hosts – Unterschiede sind dann erwartbar.</div><?php endif; ?>
    </div>
</section>

<?php if ($same): ?>
    <section class="card"><header class="card-header"><h3>Inhalt des Snapshots</h3></header><div class="card-body flush">
        <table class="table compact"><tbody><?php foreach ($records as $r): ?><tr><td><span class="badge badge-type"><?= e($r['type']) ?></span></td><td class="mono small"><?= e($r['name']) ?></td><td class="num"><?= (int) $r['ttl'] ?></td><td class="wrap"><?= copyable($r['data']) ?></td></tr><?php endforeach; ?></tbody></table>
    </div></section>
<?php elseif (!$diff['added'] && !$diff['removed']): ?>
    <div class="card"><div class="card-body"><?= ui_empty('circle-check', 'Keine Unterschiede', 'Beide Snapshots enthalten dieselben Records (TTL-Unterschiede werden ignoriert).') ?></div></div>
<?php else: ?>
    <div class="grid grid-2">
        <section class="card"><header class="card-header"><h3 class="text-ok">+ Hinzugefügt (<?= count($diff['added']) ?>)</h3></header>
            <div class="card-body flush"><table class="table compact diff-add"><tbody><?php foreach ($diff['added'] as $r): ?><tr><td><span class="badge badge-type"><?= e($r['type']) ?></span></td><td class="mono small"><?= e($r['name']) ?></td><td class="wrap"><?= copyable($r['data']) ?></td></tr><?php endforeach; ?></tbody></table></div></section>
        <section class="card"><header class="card-header"><h3 class="text-fail">− Entfernt (<?= count($diff['removed']) ?>)</h3></header>
            <div class="card-body flush"><table class="table compact diff-del"><tbody><?php foreach ($diff['removed'] as $r): ?><tr><td><span class="badge badge-type"><?= e($r['type']) ?></span></td><td class="mono small"><?= e($r['name']) ?></td><td class="wrap"><?= copyable($r['data']) ?></td></tr><?php endforeach; ?></tbody></table></div></section>
    </div>
<?php endif; ?>

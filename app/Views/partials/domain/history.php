<?php
/**
 * @var array $changes
 * @var array $jobs
 */
?>
<div class="grid grid-main">
    <section class="card">
        <header class="card-header"><h3>Erkannte Änderungen</h3></header>
        <div class="card-body">
            <?php if (!$changes): ?>
                <?= ui_empty('history', 'Noch keine Änderungen erkannt', 'Änderungen werden beim Vergleich mit dem jeweils vorherigen Snapshot erkannt – frühestens bei der zweiten Prüfung.') ?>
            <?php else: ?>
                <ol class="timeline">
                    <?php foreach ($changes as $c): ?>
                        <li><span class="tl-dot"></span><div><div><span class="badge badge-type"><?= e($c['type']) ?></span> <?= e($c['summary']) ?></div><div class="muted small"><?= e(fmt_dt($c['detected_at'], 'd.m.Y H:i')) ?> <?= e(tz_label()) ?></div></div></li>
                    <?php endforeach; ?>
                </ol>
            <?php endif; ?>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>Prüfläufe</h3></header>
        <div class="card-body flush">
            <?php if (!$jobs): ?><p class="muted pad">Keine Läufe.</p><?php else: ?>
                <table class="table compact"><tbody>
                <?php foreach ($jobs as $j): ?>
                    <tr><td class="mono small"><?= e(fmt_dt($j['started_at'], 'd.m. H:i')) ?></td><td><?= ui_pill($j['status']) ?></td><td class="small muted"><?= e($j['trigger_type'] === 'cron' ? 'Cron' : 'manuell') ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
        </div>
    </section>
</div>

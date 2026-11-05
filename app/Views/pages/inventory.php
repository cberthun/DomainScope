<?php
/**
 * @var array $assets
 * @var array $filter
 * @var int $relCount
 * @var int $unconfirmed
 */
use DomainScope\Repositories\AssetRepository;
use DomainScope\Security\Csrf;
?>
<div class="toolbar">
    <a class="btn btn-primary" href="/inventory/new"><?= icon('plus') ?> Asset anlegen</a>
    <form method="post" action="/inventory/import" class="inline"><?= Csrf::field() ?>
        <button class="btn" type="submit" title="Übernimmt gespeicherte Domains, IPs, Nameserver und Mailserver als Assets"><?= icon('download') ?> Beobachtete Daten übernehmen</button></form>
    <span class="spacer"></span>
    <span class="muted small"><?= count($assets) ?> Assets · <?= $relCount ?> Beziehungen<?= $unconfirmed ? ' · <strong>' . $unconfirmed . ' unbestätigt</strong>' : '' ?></span>
</div>

<section class="card">
    <header class="card-header"><h2>Beziehungsgraph</h2>
        <div class="legend-inline"><span><i class="line-solid"></i> manuell bestätigt</span><span><i class="line-dashed"></i> automatisch beobachtet (unbestätigt)</span></div></header>
    <div class="card-body flush">
        <div class="graph-wrap"><svg id="asset-graph" class="graph" data-src="/inventory/graph" role="img" aria-label="Beziehungsgraph der Assets"></svg><div class="graph-empty" hidden>Noch keine Beziehungen vorhanden.</div></div>
    </div>
</section>

<section class="card">
    <header class="card-header"><h2>Assets</h2>
        <form method="get" action="/inventory" class="form-inline compact">
            <input class="input input-sm" type="search" name="q" value="<?= e($filter['q']) ?>" placeholder="Suchen …" maxlength="100">
            <select class="select input-sm" name="type" onchange="this.form.submit()"><option value="">Alle Typen</option><?php foreach (AssetRepository::TYPES as $k => $l): ?><option value="<?= e($k) ?>" <?= $filter['type'] === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select>
            <select class="select input-sm" name="environment" onchange="this.form.submit()"><option value="">Alle Umgebungen</option><?php foreach (AssetRepository::ENVIRONMENTS as $k => $l): ?><option value="<?= e($k) ?>" <?= $filter['environment'] === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select>
        </form>
    </header>
    <div class="card-body flush">
        <?php if (!$assets): ?>
            <?= ui_empty('package', 'Noch keine Assets', 'Legen Sie Server, Dienste und Endpunkte an oder übernehmen Sie beobachtete Daten aus gespeicherten Domains.', '<a class="btn btn-primary" href="/inventory/new">Asset anlegen</a>') ?>
        <?php else: ?>
            <?= ui_table_open('assets-table', ['Name', 'Typ', 'Adresse', 'Anbieter', 'Umgebung', 'Tags', 'Beziehungen', 'Letzte Prüfung']) ?>
            <?php foreach ($assets as $a): ?>
                <tr><td><a href="/inventory/<?= (int) $a['id'] ?>"><?= e($a['name']) ?></a></td>
                    <td><span class="badge badge-type"><?= e(AssetRepository::TYPES[$a['type']] ?? $a['type']) ?></span></td>
                    <td class="mono small"><?= e($a['address'] ?? '–') ?></td><td class="small"><?= e($a['provider'] ?? '–') ?></td>
                    <td><?= badge(AssetRepository::ENVIRONMENTS[$a['environment']] ?? $a['environment'], $a['environment'] === 'production' ? 'info' : 'neutral') ?></td>
                    <td class="small"><?= e($a['tags']) ?></td><td class="num"><?= (int) $a['rel_count'] ?></td>
                    <td class="small"><?= $a['last_checked_at'] ? e(time_ago($a['last_checked_at'])) : '–' ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>

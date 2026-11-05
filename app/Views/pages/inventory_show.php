<?php
/**
 * @var array $asset
 * @var array $rels
 * @var array $others
 * @var ?array $linkedDomain
 */
use DomainScope\Repositories\AssetRepository;
use DomainScope\Security\Csrf;
$id = (int) $asset['id'];
?>
<div class="toolbar">
    <a class="btn" href="/inventory/<?= $id ?>/edit"><?= icon('edit') ?> Bearbeiten</a>
    <form method="post" action="/inventory/<?= $id ?>/delete" class="inline" data-confirm="Asset und seine Beziehungen wirklich löschen?"><?= Csrf::field() ?>
        <button class="btn btn-danger" type="submit"><?= icon('trash') ?> Löschen</button></form>
</div>
<div class="grid grid-2">
    <section class="card">
        <header class="card-header"><h3>Details</h3></header>
        <div class="card-body">
            <?= ui_kv([
                ['Typ', badge(AssetRepository::TYPES[$asset['type']] ?? $asset['type'], 'info')],
                ['Adresse', $asset['address'] ? (filter_var($asset['address'], FILTER_VALIDATE_IP) ? '<a class="mono" href="/ip/' . e(rawurlencode($asset['address'])) . '">' . e($asset['address']) . '</a>' : copyable($asset['address'])) : '–'],
                ['Anbieter', e($asset['provider'] ?? '–')],
                ['Umgebung', e(AssetRepository::ENVIRONMENTS[$asset['environment']] ?? $asset['environment'])],
                ['Domain', $linkedDomain ? ui_domain_link($linkedDomain['name'], $linkedDomain['unicode_name']) : '–'],
                ['Tags', $asset['tags'] ? implode(' ', array_map(static fn($t) => '<span class="chip">' . e(trim($t)) . '</span>', explode(',', $asset['tags']))) : '–'],
                ['Angelegt', e(fmt_dt($asset['created_at']))], ['Letzte Prüfung', $asset['last_checked_at'] ? e(fmt_dt($asset['last_checked_at'])) : '–'],
            ], 'kv-compact') ?>
            <?php if ($asset['description']): ?><div class="subhead">Beschreibung</div><p><?= nl2br(e($asset['description'])) ?></p><?php endif; ?>
            <?php if ($asset['notes']): ?><div class="subhead">Notizen</div><p class="pre-wrap"><?= e($asset['notes']) ?></p><?php endif; ?>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>Beziehungsgraph</h3></header>
        <div class="card-body flush"><div class="graph-wrap graph-small"><svg id="asset-graph" class="graph" data-src="/inventory/graph?focus=<?= $id ?>" data-focus="<?= $id ?>" role="img" aria-label="Beziehungen dieses Assets"></svg><div class="graph-empty" hidden>Keine Beziehungen.</div></div></div>
    </section>
</div>

<section class="card">
    <header class="card-header"><h3>Beziehungen</h3></header>
    <div class="card-body flush">
        <?php if (!$rels): ?><p class="muted pad">Noch keine Beziehungen.</p><?php else: ?>
            <table class="table compact"><thead><tr><th>Von</th><th>Beziehung</th><th>Nach</th><th>Herkunft</th><th></th></tr></thead><tbody>
            <?php foreach ($rels as $e): ?>
                <tr><td><a href="/inventory/<?= (int) $e['from_asset_id'] ?>"><?= e($e['from_name']) ?></a></td>
                    <td><?= e(AssetRepository::RELATIONS[$e['relation']] ?? $e['relation']) ?></td>
                    <td><a href="/inventory/<?= (int) $e['to_asset_id'] ?>"><?= e($e['to_name']) ?></a></td>
                    <td><?= $e['confirmed'] ? badge('manuell bestätigt', 'ok') : badge('automatisch beobachtet', 'warn') ?> <span class="muted small"><?= e($e['note'] ?? '') ?></span></td>
                    <td class="row gap">
                        <?php if (!$e['confirmed']): ?><form method="post" action="/inventory/link/<?= (int) $e['id'] ?>/confirm" class="inline"><?= Csrf::field() ?><input type="hidden" name="back" value="/inventory/<?= $id ?>"><button class="btn btn-sm" type="submit"><?= icon('check') ?> Bestätigen</button></form><?php endif; ?>
                        <form method="post" action="/inventory/link/<?= (int) $e['id'] ?>/delete" class="inline"><?= Csrf::field() ?><input type="hidden" name="back" value="/inventory/<?= $id ?>"><button class="btn btn-sm btn-ghost" type="submit" aria-label="Beziehung entfernen"><?= icon('x') ?></button></form></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php endif; ?>
    </div>
</section>

<section class="card">
    <header class="card-header"><h3>Beziehung hinzufügen</h3></header>
    <div class="card-body">
        <form method="post" action="/inventory/<?= $id ?>/link" class="form-inline">
            <?= Csrf::field() ?>
            <label class="field"><span>Richtung</span><select class="select" name="direction"><option value="out">Dieses Asset → anderes</option><option value="in">Anderes → dieses Asset</option></select></label>
            <label class="field"><span>Beziehung</span><select class="select" name="relation"><?php foreach (AssetRepository::RELATIONS as $k => $l): ?><option value="<?= e($k) ?>"><?= e($l) ?></option><?php endforeach; ?></select></label>
            <label class="field grow"><span>Anderes Asset</span><select class="select" name="to" required><option value="">– wählen –</option><?php foreach ($others as $o): ?><option value="<?= (int) $o['id'] ?>"><?= e($o['name']) ?> (<?= e(AssetRepository::TYPES[$o['type']] ?? $o['type']) ?>)</option><?php endforeach; ?></select></label>
            <label class="field grow"><span>Notiz</span><input class="input" name="note" maxlength="250"></label>
            <button class="btn btn-primary" type="submit"><?= icon('link') ?> Verknüpfen</button>
        </form>
    </div>
</section>

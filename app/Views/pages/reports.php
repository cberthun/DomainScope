<?php
/**
 * @var array $types
 * @var array $domains
 */
?>
<div class="grid grid-2">
<?php foreach ($types as $key => [$title, $desc]): ?>
    <section class="card">
        <header class="card-header"><h3><?= icon('bar-chart') ?> <?= e($title) ?></h3></header>
        <div class="card-body stack-sm">
            <p class="small muted"><?= e($desc) ?></p>
            <?php if ($key === 'inventory'): ?>
                <div class="row gap wrap-row">
                    <a class="btn btn-primary btn-sm" href="/reports/inventory/alle">Bericht öffnen</a>
                    <a class="btn btn-sm" href="/reports/inventory/alle?format=json">JSON</a>
                    <a class="btn btn-sm" href="/reports/inventory/alle?format=csv">CSV</a>
                </div>
            <?php elseif (!$domains): ?>
                <p class="muted small">Zuerst eine Domain erfassen.</p>
            <?php else: ?>
                <form class="form-inline report-form" data-report-type="<?= e($key) ?>">
                    <label class="field grow"><span class="sr-only">Domain</span>
                        <select class="select" name="domain"><?php foreach ($domains as $d): ?><option value="<?= e($d['name']) ?>"><?= e($d['unicode_name']) ?></option><?php endforeach; ?></select></label>
                    <button class="btn btn-primary btn-sm" type="submit" data-fmt="html">Öffnen</button>
                    <button class="btn btn-sm" type="submit" data-fmt="json">JSON</button>
                    <button class="btn btn-sm" type="submit" data-fmt="csv">CSV</button>
                </form>
            <?php endif; ?>
        </div>
    </section>
<?php endforeach; ?>
</div>
<section class="card"><div class="card-body small muted">Berichte enthalten stets Erstellungszeitpunkt, Datenquellen und bekannte Einschränkungen. Die HTML-Ansicht ist druckoptimiert (Drucken → „Als PDF speichern“). Die Berichte basieren auf gespeicherten Prüfungen; veraltete Daten vorher aktualisieren.</div></section>

<?php
/**
 * @var ?array $domain
 * @var array $domains
 * @var array $snapshots
 */
?>
<section class="card">
    <div class="card-body">
        <form method="get" action="/dns/snapshots" class="form-inline">
            <label class="field grow"><span>Domain</span>
                <select class="select" name="domain" onchange="this.form.submit()">
                    <option value="">– wählen –</option>
                    <?php foreach ($domains as $d): ?><option value="<?= e($d['name']) ?>" <?= $domain && $domain['id'] === $d['id'] ? 'selected' : '' ?>><?= e($d['unicode_name']) ?></option><?php endforeach; ?>
                </select></label>
            <button class="btn" type="submit">Anzeigen</button>
        </form>
    </div>
</section>

<?php if ($domain): ?>
<section class="card">
    <header class="card-header"><h3>Snapshots von <?= e($domain['unicode_name']) ?></h3></header>
    <div class="card-body flush">
        <?php if (!$snapshots): ?>
            <?= ui_empty('git-compare', 'Keine Snapshots', 'Erstellen Sie einen DNS-Snapshot über die Domain-Detailseite.') ?>
        <?php else: ?>
            <form method="get" action="/dns/compare" id="compare-form">
                <table class="table compact"><thead><tr><th>A</th><th>B</th><th>Zeit (Ortszeit)</th><th>Host</th><th>Resolver</th><th class="num">Records</th></tr></thead><tbody>
                <?php foreach ($snapshots as $i => $s): ?>
                    <tr><td><input type="radio" name="a" value="<?= (int) $s['id'] ?>" <?= $i === 1 ? 'checked' : '' ?> required></td>
                        <td><input type="radio" name="b" value="<?= (int) $s['id'] ?>" <?= $i === 0 ? 'checked' : '' ?> required></td>
                        <td class="mono small"><?= e(fmt_dt($s['taken_at'], 'd.m.Y H:i:s')) ?></td><td class="mono small"><?= e($s['host']) ?></td>
                        <td><?= e($s['resolver']) ?></td><td class="num"><?= (int) $s['record_count'] ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
                <div class="pad"><button class="btn btn-primary" type="submit"><?= icon('git-compare') ?> Auswahl vergleichen</button>
                <span class="muted small">Der Vergleich ignoriert TTL-Änderungen. Beide Snapshots müssen zur selben Domain gehören.</span></div>
            </form>
        <?php endif; ?>
    </div>
</section>
<?php endif; ?>

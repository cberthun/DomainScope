<?php
/**
 * @var array $domain
 * @var string $host
 * @var int $staleHours
 * @var array $snaps
 * @var array $history
 * @var ?array $consistency
 */
$base = '/domain/' . rawurlencode($domain['name']);
?>
<div class="toolbar">
    <?= ui_run_button($domain, 'dns', 'DNS-Snapshot jetzt erstellen', $host !== $domain['name'] ? ['host' => $host] : [], 'btn btn-primary btn-sm') ?>
    <a class="btn btn-sm" href="/dns?name=<?= e(rawurlencode($host)) ?>"><?= icon('network') ?> Im DNS Explorer öffnen</a>
    <a class="btn btn-sm" href="/dns/snapshots?domain=<?= e(rawurlencode($domain['name'])) ?>"><?= icon('git-compare') ?> Snapshots vergleichen</a>
</div>

<?php if ($consistency): ?>
    <div class="alert alert-<?= $consistency['status'] === 'pass' ? 'success' : 'warn' ?>">
        <strong>Resolver-Vergleich (Cloudflare ↔ Google):</strong> <?= e($consistency['summary']) ?> <span class="muted small"><?= e(time_ago($consistency['checked_at'])) ?></span>
        <?php if ($consistency['status'] !== 'pass'): ?>
            <ul class="small">
                <?php foreach ($consistency['data']['diffs'] ?? [] as $type => $d): ?>
                    <li><strong><?= e($type) ?>:</strong> nur Cloudflare: <span class="mono"><?= e(implode(', ', $d['only_a']) ?: '–') ?></span> · nur Google: <span class="mono"><?= e(implode(', ', $d['only_b']) ?: '–') ?></span></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
<?php endif; ?>

<?php if (!$snaps): ?>
    <div class="card"><div class="card-body"><?= ui_empty('network', 'Noch kein DNS-Snapshot', 'Erstellen Sie einen Snapshot, um die aktuellen Records zu speichern und spätere Änderungen zu erkennen.') ?></div></div>
<?php endif; ?>

<?php foreach ($snaps as $h => $s): ?>
    <section class="card">
        <header class="card-header">
            <h3 class="mono"><?= e($h) ?></h3>
            <span class="muted small"><?= (int) $s['snapshot']['record_count'] ?> Records · Resolver <?= e($s['snapshot']['resolver']) ?> · <?= ui_freshness($s['snapshot']['taken_at'], $staleHours) ?></span>
        </header>
        <div class="card-body flush">
            <?php if (!$s['records']): ?>
                <p class="muted pad">Keine Records (Name existiert nicht oder hat keine Daten der abgefragten Typen).</p>
            <?php else: ?>
                <?= ui_table_open('snap-' . substr(md5($h), 0, 6), ['Typ', 'Name', 'TTL', 'Daten']) ?>
                <?php foreach ($s['records'] as $rec): ?>
                    <tr><td><span class="badge badge-type"><?= e($rec['type']) ?></span></td>
                        <td class="mono small"><?= e($rec['name']) ?></td>
                        <td class="num mono"><?= (int) $rec['ttl'] ?></td>
                        <td class="wrap"><?= copyable($rec['data']) ?></td></tr>
                <?php endforeach; ?>
                <?= ui_table_close() ?>
            <?php endif; ?>
        </div>
    </section>
<?php endforeach; ?>

<?php if ($history): ?>
<section class="card">
    <header class="card-header"><h3>Snapshot-Verlauf</h3></header>
    <div class="card-body flush">
        <table class="table compact"><thead><tr><th>Zeit</th><th>Host</th><th>Resolver</th><th class="num">Records</th><th></th></tr></thead><tbody>
        <?php foreach ($history as $h): ?>
            <tr><td class="mono small"><?= e(fmt_dt($h['taken_at'], 'd.m.Y H:i:s')) ?></td><td class="mono small"><?= e($h['host']) ?></td><td><?= e($h['resolver']) ?></td>
                <td class="num"><?= (int) $h['record_count'] ?></td>
                <td><a href="/dns/compare?a=<?= (int) $h['id'] ?>&b=<?= (int) $h['id'] ?>" class="small">anzeigen</a></td></tr>
        <?php endforeach; ?>
        </tbody></table>
        <p class="muted small pad">Identische Zustände werden nicht erneut gespeichert; es wird nur der Prüfzeitpunkt des letzten Snapshots aktualisiert.</p>
    </div>
</section>
<?php endif; ?>

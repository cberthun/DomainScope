<?php
/**
 * @var array $domains
 * @var array $changes
 * @var array $jobs
 * @var ?array $lastCron
 * @var int $staleHours
 * @var string $type
 * @var ?int $domainId
 * @var int $snapCount
 * @var string $phpBin
 * @var string $root
 */
use DomainScope\Security\Csrf;
$stale = array_filter($domains, static fn($d) => $d['monitored'] && (!$d['last_checked_at'] || strtotime($d['last_checked_at'] . ' UTC') < time() - $staleHours * 3600));
?>
<?php if ($stale): ?>
    <div class="alert alert-warn"><strong><?= count($stale) ?> überwachte Domain(s)</strong> wurden seit mehr als <?= $staleHours ?> Stunden nicht geprüft: <?= e(implode(', ', array_map(static fn($d) => $d['unicode_name'], array_slice($stale, 0, 5)))) ?>. Läuft der Cronjob?</div>
<?php endif; ?>

<div class="grid grid-main">
<section class="card">
    <header class="card-header"><h2>Überwachte Domains</h2><span class="muted small"><?= $snapCount ?> DNS-Snapshots gespeichert</span></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('activity', 'Keine Domains', 'Domains im Domain Explorer anlegen und die Überwachung aktivieren.') ?>
        <?php else: ?>
            <table class="table compact"><thead><tr><th>Domain</th><th>Überwacht</th><th>Letzte Prüfung</th><th></th></tr></thead><tbody>
            <?php foreach ($domains as $d): ?>
                <tr><td><?= ui_domain_link($d['name'], $d['unicode_name']) ?></td>
                    <td><form method="post" action="/monitoring/run" class="inline"><?= Csrf::field() ?><input type="hidden" name="domain" value="<?= e($d['name']) ?>"><input type="hidden" name="action" value="toggle">
                        <button type="submit" class="btn btn-sm btn-ghost"><?= $d['monitored'] ? badge('ja', 'ok') : badge('nein', 'neutral') ?></button></form></td>
                    <td><?= ui_freshness($d['last_checked_at'], $staleHours) ?></td>
                    <td><form method="post" action="/monitoring/run" class="inline" data-ajax-run><?= Csrf::field() ?><input type="hidden" name="domain" value="<?= e($d['name']) ?>">
                        <button type="submit" class="btn btn-sm"><?= icon('play') ?> Jetzt prüfen</button></form></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php endif; ?>
    </div>
</section>
<section class="card">
    <header class="card-header"><h2>Cronjob</h2></header>
    <div class="card-body stack-sm">
        <p class="small">Regelmäßige Prüfungen laufen ausschließlich über die Kommandozeile – es gibt keine per URL aufrufbare Cron-Schnittstelle.</p>
        <pre class="code">0,30 * * * * <?= e($phpBin) ?> <?= e($root) ?>/bin/cron.php</pre>
        <p class="small muted">Das Skript prüft jeweils die überwachten Domains, deren letzte Prüfung älter als das Intervall ist (Standard: 6 Stunden; <span class="mono">--interval=Stunden</span>, <span class="mono">--force</span>, <span class="mono">--domain=example.com</span>).</p>
        <p class="small">Letzter Cron-Lauf: <?= $lastCron ? ui_freshness($lastCron['started_at'], $staleHours) . ' · ' . ui_pill($lastCron['status']) : '<span class="muted">noch nie</span>' ?></p>
    </div>
</section>
</div>

<section class="card">
    <header class="card-header"><h2>Erkannte Änderungen</h2>
        <form method="get" action="/monitoring" class="form-inline compact">
            <select class="select input-sm" name="domain_id" onchange="this.form.submit()"><option value="">Alle Domains</option><?php foreach ($domains as $d): ?><option value="<?= (int) $d['id'] ?>" <?= $domainId === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['unicode_name']) ?></option><?php endforeach; ?></select>
            <select class="select input-sm" name="type" onchange="this.form.submit()"><option value="">Alle Arten</option>
                <?php foreach (['dns' => 'DNS', 'email' => 'E-Mail (SPF/DMARC)', 'ip' => 'IP-Zuordnung', 'tls' => 'Zertifikate', 'registration' => 'Registrierung', 'subdomain' => 'Subdomains', 'dnssec' => 'DNSSEC'] as $k => $l): ?><option value="<?= e($k) ?>" <?= $type === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select>
        </form></header>
    <div class="card-body">
        <?php if (!$changes): ?>
            <?= ui_empty('history', 'Noch keine Änderungen', 'Änderungen entstehen aus dem Vergleich aufeinanderfolgender Snapshots: neue/entfernte DNS-Records, MX/NS, SPF/DMARC, neue Zertifikate, neue Subdomains, geänderte IP-Zuordnungen und Domainstatus.') ?>
        <?php else: ?>
            <ol class="timeline"><?php foreach ($changes as $c): ?>
                <li><span class="tl-dot"></span><div><div><span class="badge badge-type"><?= e($c['type']) ?></span> <strong><?= e($c['domain_name']) ?></strong> – <?= e($c['summary']) ?></div>
                    <div class="muted small"><?= e(fmt_dt($c['detected_at'], 'd.m.Y H:i')) ?> <?= e(tz_label()) ?> · <?= e(time_ago($c['detected_at'])) ?></div></div></li>
            <?php endforeach; ?></ol>
        <?php endif; ?>
    </div>
</section>

<section class="card">
    <header class="card-header"><h2>Prüfläufe</h2></header>
    <div class="card-body flush">
        <?php if (!$jobs): ?><p class="muted pad">Noch keine Prüfläufe.</p><?php else: ?>
            <table class="table compact"><thead><tr><th>Start</th><th>Domain</th><th>Auslöser</th><th>Ergebnis</th><th>Module</th></tr></thead><tbody>
            <?php foreach ($jobs as $j): ?>
                <tr><td class="mono small"><?= e(fmt_dt($j['started_at'], 'd.m. H:i:s')) ?></td><td><?= $j['domain_name'] ? ui_domain_link($j['domain_name']) : '–' ?></td>
                    <td class="small"><?= $j['trigger_type'] === 'cron' ? 'Cron' : 'Manuell' ?></td><td><?= ui_pill($j['status']) ?></td>
                    <td class="small"><?php foreach ($j['results'] as $m): ?><span class="chip <?= $m['status'] === 'ok' ? 'chip-ok' : 'chip-bad' ?>" title="<?= e($m['message']) ?> (<?= (int) $m['duration_ms'] ?> ms)"><?= e($m['module']) ?></span> <?php endforeach; ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php endif; ?>
    </div>
</section>

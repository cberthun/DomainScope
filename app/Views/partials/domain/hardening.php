<?php
/**
 * @var array $domain
 * @var ?array $hardening  module_results-Zeile (data = HardeningService::run)
 * @var int $staleHours
 */
use DomainScope\Security\Csrf;
$lvl = static fn(string $l) => match ($l) { 'fail' => 'circle-x', 'warn' => 'alert-triangle', 'pass' => 'circle-check', 'unknown' => 'circle-help', default => 'info' };
$list = static function (array $findings) use ($lvl): string {
    if (!$findings) {
        return '<p class="muted small">Keine Hinweise.</p>';
    }
    $h = '<ul class="check-findings">';
    foreach ($findings as $f) {
        $h .= '<li class="cf cf-' . e($f['level']) . '">' . icon($lvl($f['level'])) . '<div><div>' . e($f['message']) . '</div>'
            . (!empty($f['recommendation']) ? '<div class="cf-meta"><strong>Empfehlung:</strong> ' . e($f['recommendation']) . '</div>' : '') . '</div></li>';
    }
    return $h . '</ul>';
};
?>
<div class="toolbar">
    <?= ui_run_button($domain, 'hardening', 'CAA & DANE prüfen', [], 'btn btn-primary btn-sm', 'play') ?>
    <?= ui_run_button($domain, 'hardening', 'Inkl. STARTTLS-Test (Port 25)', ['starttls' => '1'], 'btn btn-sm', 'mail') ?>
    <span class="muted small">Der STARTTLS-Test verbindet sich aktiv mit den MX-Servern auf Port 25, ohne eine Mail zu senden. Viele Provider sperren ausgehenden Port 25.</span>
</div>
<?php if (!$hardening): ?>
    <div class="card"><div class="card-body"><?= ui_empty('lock', 'Noch keine Härtungsprüfung', 'Geprüft werden CAA-Records, DANE/TLSA und optional STARTTLS der Mailserver.') ?></div></div>
<?php else: $h = $hardening['data']; ?>
    <div class="summary-bar"><?= ui_freshness($hardening['checked_at'], $staleHours) ?></div>
    <section class="card">
        <header class="card-header"><h3>CAA (Certification Authority Authorization)</h3><?= $h['caa']['records'] ? badge(count($h['caa']['records']) . ' Record(s)', 'ok') : badge('keiner', 'neutral') ?></header>
        <div class="card-body stack-sm">
            <?php if ($h['caa']['records']): ?>
                <table class="table compact"><thead><tr><th>Flags</th><th>Tag</th><th>Wert</th></tr></thead><tbody>
                <?php foreach ($h['caa']['records'] as $c): ?><tr><td class="mono"><?= (int) $c['flags'] ?></td><td class="mono"><?= e($c['tag']) ?></td><td><?= copyable($c['value']) ?></td></tr><?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
            <?= $list($h['caa']['findings']) ?>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>DANE / TLSA</h3><?= $h['tlsa']['records'] ? badge(count($h['tlsa']['records']) . ' Record(s)', 'ok') : badge('keiner', 'neutral') ?></header>
        <div class="card-body stack-sm">
            <p class="muted small">Geprüft: <?= e(implode(', ', $h['tlsa']['checked'])) ?></p>
            <?php foreach ($h['tlsa']['records'] as $r): ?><div><span class="badge badge-type"><?= e($r['service']) ?></span> <span class="mono small"><?= e($r['name']) ?></span> <?= copyable($r['data']) ?></div><?php endforeach; ?>
            <?= $list($h['tlsa']['findings']) ?>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>STARTTLS der Mailserver</h3><?= $h['starttls'] ? badge('geprüft', 'ok') : badge('nicht ausgeführt', 'neutral') ?></header>
        <div class="card-body stack-sm">
            <?php if (!$h['starttls']): ?>
                <p class="muted">Der aktive Test wurde noch nicht ausgelöst („Inkl. STARTTLS-Test“ oben).</p>
            <?php else: ?>
                <table class="table compact"><thead><tr><th>MX-Host</th><th>IP</th><th>Status</th><th>Protokoll</th><th>Zertifikat</th><th>Hostname</th><th>Kette</th></tr></thead><tbody>
                <?php foreach ($h['starttls']['hosts'] as $x): ?>
                    <tr><td class="mono"><?= e($x['host']) ?></td><td class="mono small"><?= e($x['ip'] ?? '–') ?></td>
                        <td><?= match ($x['status']) { 'ok' => ui_pill('ok', 'STARTTLS ok'), 'invalid' => ui_pill('warn', 'Zertifikat auffällig'), 'no_starttls' => ui_pill('fail', 'kein STARTTLS'), 'tls_failed' => ui_pill('warn', 'TLS fehlgeschlagen'), default => ui_pill('error', 'nicht erreichbar') } ?></td>
                        <td class="mono small"><?= e($x['protocol'] ?? '–') ?></td>
                        <td class="small"><?= $x['certificate'] ? e(fmt_dt($x['certificate']['not_after'], 'd.m.Y')) . ' ' . ui_days_badge($x['days_left']) : '–' ?></td>
                        <td><?= $x['hostname_match'] === null ? '–' : ($x['hostname_match'] ? badge('passt', 'ok') : badge('passt nicht', 'warn')) ?></td>
                        <td><?= $x['chain_trusted'] === null ? '–' : ($x['chain_trusted'] ? badge('vertrauenswürdig', 'ok') : badge('nicht vertrauenswürdig', 'warn')) ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
                <?= $list($h['starttls']['findings']) ?>
            <?php endif; ?>
        </div>
    </section>
<?php endif; ?>

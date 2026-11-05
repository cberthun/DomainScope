<?php
/**
 * @var array $domain
 * @var array $results
 * @var string $host
 */
?>
<div class="toolbar">
    <?= ui_run_button($domain, 'http', 'HTTP jetzt prüfen', $host !== $domain['name'] ? ['host' => $host] : [], 'btn btn-primary btn-sm', 'play') ?>
</div>
<?php if (!$results): ?>
    <div class="card"><div class="card-body"><?= ui_empty('globe', 'Noch keine HTTP-Prüfung', 'Geprüft werden HTTP und HTTPS inklusive Weiterleitungsketten. Jede Weiterleitung wird erneut gegen interne Ziele geprüft (SSRF-Schutz).') ?></div></div>
<?php endif; ?>
<?php foreach ($results as $row): $h = $row['data']; ?>
    <section class="card">
        <header class="card-header"><h3 class="mono"><?= e($row['subject']) ?></h3><?= ui_freshness($row['checked_at']) ?></header>
        <div class="card-body stack-sm">
            <div class="grid grid-2">
                <?php foreach (['https' => 'HTTPS', 'http' => 'HTTP'] as $k => $label): $p = $h[$k]; ?>
                    <div>
                        <div class="subhead"><?= $label ?></div>
                        <?php if ($p['reachable']): ?>
                            <?= ui_kv([
                                ['Status', badge('HTTP ' . $p['status'], $p['status'] < 400 ? 'ok' : ($p['status'] < 500 ? 'warn' : 'fail'))],
                                ['Endgültige URL', copyable($p['final_url'])],
                                ['IP', '<a class="mono" href="/ip/' . e(rawurlencode((string) $p['ip'])) . '">' . e($p['ip']) . '</a> · ' . (int) $p['ms'] . ' ms'],
                                ['Server', e($p['headers']['server'] ?? '–')],
                                ['Titel', e($p['title'] ?? '–')],
                            ], 'kv-compact') ?>
                            <?php if (count($p['redirects']) > 1): ?>
                                <ol class="chain small"><?php foreach ($p['redirects'] as $step): ?><li><span class="badge badge-type"><?= (int) $step['status'] ?></span> <span class="mono"><?= e($step['url']) ?></span></li><?php endforeach; ?></ol>
                            <?php endif; ?>
                        <?php else: ?>
                            <p><?= badge('nicht erreichbar', 'unknown') ?> <span class="small muted"><?= e($p['error'] ?? '') ?></span></p>
                            <?php if (($p['error_code'] ?? '') === 'tls'): ?><p class="small">TLS-Fehler – das ist ein Zertifikatsproblem, nicht zwingend eine Nichterreichbarkeit des Hosts.</p><?php endif; ?>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php if ($h['https']['reachable']): ?>
                <div class="subhead">Sicherheits-Header (HTTPS-Antwort)</div>
                <div class="chips"><?php foreach ($h['security_headers'] as $sh): ?><span class="chip <?= $sh['present'] ? 'chip-ok' : 'chip-off' ?>" title="<?= e($sh['value'] ?? 'nicht gesetzt') ?>"><?= $sh['present'] ? '✓' : '–' ?> <?= e($sh['header']) ?></span><?php endforeach; ?></div>
                <p class="muted small">HTTP→HTTPS-Weiterleitung: <?= $h['http_redirects_to_https'] === null ? 'nicht beurteilbar' : ($h['http_redirects_to_https'] ? 'ja' : 'nein') ?><?= $h['hsts'] ? ' · HSTS: ' . e($h['hsts']) : '' ?></p>
            <?php endif; ?>
        </div>
    </section>
<?php endforeach; ?>

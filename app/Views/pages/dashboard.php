<?php
/**
 * @var array $stats
 * @var array $severity
 * @var array $problems
 * @var array $timeline
 * @var array $jobs
 * @var array $failed
 * @var array $sources
 * @var array $expiring
 * @var array $expiringDomains
 * @var array $domains
 * @var array $activity
 * @var array $perDay
 * @var int $staleHours
 */
$tile = static fn(string $label, mixed $value, string $icon, string $href = '', string $sub = '', string $kind = '') =>
    '<a class="stat ' . e($kind) . '"' . ($href ? ' href="' . e($href) . '"' : '') . '>' . icon($icon) . '<div><div class="stat-value">' . e((string) $value) . '</div><div class="stat-label">' . e($label) . '</div>'
    . ($sub ? '<div class="stat-sub">' . e($sub) . '</div>' : '') . '</div></a>';
$sevOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
$sevTotal = max(1, array_sum($severity));
?>
<?php if ($stats['domains'] === 0): ?>
    <div class="card"><div class="card-body">
        <?= ui_empty('globe', 'Noch keine Domains erfasst', 'Geben Sie im Domain Explorer eine Domain ein, um die erste Prüfung durchzuführen. Das Dashboard füllt sich ausschließlich mit tatsächlich ermittelten Daten.', '<a class="btn btn-primary" href="/domains">Domain Explorer öffnen</a>') ?>
    </div></div>
<?php endif; ?>

<section class="stats-grid" aria-label="Kennzahlen">
    <?= $tile('Domains', $stats['domains'], 'globe', '/domains', $stats['monitored'] . ' überwacht') ?>
    <?= $tile('Subdomains (passiv erkannt)', $stats['subdomains'], 'git-branch', '/subdomains') ?>
    <?= $tile('IP-Adressen', $stats['ips'], 'server', '/ips') ?>
    <?= $tile('Nameserver', $stats['nameservers'], 'network', '/dns') ?>
    <?= $tile('Mailserver', $stats['mailservers'], 'mail', '/email') ?>
    <?= $tile('Zertifikate', $stats['certificates'], 'lock', '/tls') ?>
    <?= $tile('Bald ablaufend', $stats['expiring_certs'], 'clock', '/tls', 'Schwelle ' . (\DomainScope\Support\Settings::days('cert_warn_days')[0] ?? 30) . ' Tage', $stats['expiring_certs'] > 0 ? 'stat-warn' : '') ?>
    <?= $tile('Offene Findings', $stats['open_findings'], 'alert-triangle', '/findings', $stats['new_findings'] . ' neu (7 Tage)', ($severity['critical'] + $severity['high']) > 0 ? 'stat-fail' : '') ?>
    <?= $tile('E-Mail-Probleme', $stats['email_issues'], 'mail', '/findings?module=email&status=active', 'mittel oder höher', $stats['email_issues'] > 0 ? 'stat-warn' : '') ?>
    <?= $tile('DNS-Änderungen', $stats['dns_changes'], 'git-compare', '/monitoring', 'letzte 7 Tage') ?>
    <?= $tile('Fehlgeschlagene Prüfungen', $stats['failed_jobs'], 'circle-x', '/monitoring', 'von ' . $stats['jobs_7d'] . ' in 7 Tagen', $stats['failed_jobs'] > 0 ? 'stat-warn' : '') ?>
    <?= $tile('DNSSEC signiert', $stats['dnssec']['signed'], 'shield-check', '/dnssec', $stats['dnssec']['unsigned'] . ' unsigniert · ' . $stats['dnssec']['broken'] . ' defekt' . ($stats['dnssec']['unchecked'] ? ' · ' . $stats['dnssec']['unchecked'] . ' ungeprüft' : ''), $stats['dnssec']['broken'] > 0 ? 'stat-fail' : '') ?>
</section>

<div class="grid grid-main">
    <section class="card">
        <header class="card-header"><h2>Priorisierte Probleme</h2><a class="btn btn-ghost btn-sm" href="/findings">Alle Findings</a></header>
        <div class="card-body flush">
            <?php if (!$problems): ?>
                <?= ui_empty('circle-check', 'Keine offenen Findings', $stats['domains'] ? 'Bei den bisherigen Prüfungen wurde nichts festgestellt. Findings entstehen nur aus tatsächlich gemessenen Befunden.' : 'Noch keine Prüfungen durchgeführt.') ?>
            <?php else: ?>
                <ul class="problem-list">
                    <?php foreach ($problems as $f): ?>
                        <li><?= sev_badge($f['severity']) ?>
                            <a href="/findings/<?= (int) $f['id'] ?>"><?= e($f['title']) ?></a>
                            <span class="muted small"><?= e($f['domain_name'] ?? '') ?><?= $f['subject'] ? ' · ' . e($f['subject']) : '' ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h2>Schweregrade</h2></header>
        <div class="card-body">
            <div class="sev-bar" role="img" aria-label="Verteilung der offenen Findings nach Schweregrad">
                <?php foreach ($sevOrder as $s): if ($severity[$s] > 0): ?>
                    <span class="sev-seg sev-bg-<?= e($s) ?>" style="flex: <?= (int) $severity[$s] ?>" title="<?= e(severity_label($s)) ?>: <?= (int) $severity[$s] ?>"></span>
                <?php endif; endforeach; ?>
                <?php if (array_sum($severity) === 0): ?><span class="sev-seg sev-bg-empty" style="flex: 1"></span><?php endif; ?>
            </div>
            <ul class="legend">
                <?php foreach ($sevOrder as $s): ?>
                    <li><a href="/findings?severity=<?= e($s) ?>&status=active"><span class="dot sev-bg-<?= e($s) ?>"></span><?= e(severity_label($s)) ?></a><strong><?= (int) $severity[$s] ?></strong></li>
                <?php endforeach; ?>
            </ul>
            <div class="chart-title">Neue Findings pro Tag (14 Tage)</div>
            <div class="spark" data-chart="bars" data-values="<?= e(json_out(array_values($perDay))) ?>" data-labels="<?= e(json_out(array_keys($perDay))) ?>"></div>
        </div>
    </section>
</div>

<div class="grid grid-2">
    <section class="card">
        <header class="card-header"><h2>Zeitleiste</h2><a class="btn btn-ghost btn-sm" href="/monitoring">Verlauf</a></header>
        <div class="card-body">
            <?php if (!$timeline): ?>
                <?= ui_empty('history', 'Noch keine Ereignisse', 'Änderungen und neue Findings erscheinen hier, sobald Prüfungen wiederholt werden.') ?>
            <?php else: ?>
                <ol class="timeline">
                    <?php foreach ($timeline as $t): ?>
                        <li class="tl-<?= e($t['kind']) ?>">
                            <span class="tl-dot <?= $t['severity'] ? 'sev-bg-' . e($t['severity']) : '' ?>"></span>
                            <div>
                                <div><?= $t['kind'] === 'finding' ? '<a href="/findings/' . (int) $t['ref_id'] . '">' . e($t['text']) . '</a>' : e($t['text']) ?></div>
                                <div class="muted small"><?= e($t['domain_name'] ?? '') ?> · <?= e(time_ago($t['at'])) ?> · <?= $t['kind'] === 'finding' ? 'Neues Finding' : 'Änderung' ?></div>
                            </div>
                        </li>
                    <?php endforeach; ?>
                </ol>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h2>Ablaufende Zertifikate & Domains</h2></header>
        <div class="card-body flush">
            <?php if (!$expiring && !$expiringDomains): ?>
                <?= ui_empty('circle-check', 'Nichts läuft bald ab', 'Innerhalb der konfigurierten Schwellen läuft nichts aus (soweit geprüft).') ?>
            <?php else: ?>
                <table class="table compact"><tbody>
                    <?php foreach ($expiring as $c): ?>
                        <tr><td><?= icon('lock') ?> <a href="/tls/<?= e(rawurlencode($c['domain_name'])) ?>" class="mono"><?= e($c['host']) ?>:<?= (int) $c['port'] ?></a></td>
                            <td class="mono small"><?= e(fmt_dt($c['not_after'], 'd.m.Y')) ?></td><td><?= ui_days_badge(days_until($c['not_after'] . ' UTC')) ?></td></tr>
                    <?php endforeach; ?>
                    <?php foreach ($expiringDomains as $x): ?>
                        <tr><td><?= icon('globe') ?> <a href="/rdap/<?= e(rawurlencode($x['domain_name'])) ?>" class="mono"><?= e($x['domain_name']) ?></a></td>
                            <td class="mono small"><?= e(fmt_dt($x['expires_at'], 'd.m.Y')) ?></td><td><?= ui_days_badge(days_until($x['expires_at'] . ' UTC')) ?></td></tr>
                    <?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
        </div>
    </section>
</div>

<div class="grid grid-2">
    <section class="card">
        <header class="card-header"><h2>Letzte Prüfungen</h2><a class="btn btn-ghost btn-sm" href="/monitoring">Alle</a></header>
        <div class="card-body flush">
            <?php if (!$jobs): ?>
                <?= ui_empty('activity', 'Noch keine Prüfungen', 'Starten Sie eine Prüfung in der Domain-Detailansicht oder per Cron.') ?>
            <?php else: ?>
                <table class="table compact"><tbody>
                    <?php foreach ($jobs as $j): ?>
                        <tr><td><?= $j['domain_name'] ? ui_domain_link($j['domain_name']) : '–' ?></td>
                            <td><?= ui_pill($j['status']) ?></td>
                            <td class="muted small"><?= e($j['trigger_type'] === 'cron' ? 'Cron' : 'Manuell') ?></td>
                            <td class="muted small"><?= ui_freshness($j['started_at'], $staleHours) ?></td></tr>
                    <?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
            <?php if ($failed): ?>
                <div class="subhead">Fehlgeschlagene Module</div>
                <ul class="plain-list small">
                    <?php foreach ($failed as $fr): ?>
                        <li><?= icon('circle-x') ?> <strong><?= e($fr['domain_name'] ?? '–') ?></strong> · <?= e($fr['module']) ?>: <?= e(mb_strimwidth((string) $fr['message'], 0, 100, '…')) ?> <span class="muted"><?= e(time_ago($fr['started_at'])) ?></span></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h2>Datenquellen</h2></header>
        <div class="card-body flush">
            <?php if (!$sources): ?>
                <?= ui_empty('database', 'Noch keine Abfragen', 'Der Status der externen Quellen wird bei der ersten Prüfung erfasst.') ?>
            <?php else: ?>
                <table class="table compact">
                    <thead><tr><th>Quelle</th><th>Status</th><th class="num">Erfolg/Fehler</th><th class="num">Ø ms</th></tr></thead>
                    <tbody>
                    <?php foreach ($sources as $s):
                        $lastOk = $s['last_ok_at'] ? strtotime($s['last_ok_at'] . ' UTC') : 0;
                        $lastErr = $s['last_error_at'] ? strtotime($s['last_error_at'] . ' UTC') : 0;
                        $state = $lastErr > $lastOk ? 'fail' : 'ok'; ?>
                        <tr><td><?= e($s['label']) ?></td>
                            <td><?= $state === 'ok' ? ui_pill('ok', 'erreichbar') : '<span title="' . e($s['last_error']) . '">' . ui_pill('fail', 'zuletzt Fehler') . '</span>' ?></td>
                            <td class="num mono"><?= (int) $s['ok_count'] ?>/<?= (int) $s['fail_count'] ?></td>
                            <td class="num mono"><?= $s['avg_ms'] !== null ? (int) $s['avg_ms'] : '–' ?></td></tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </section>
</div>

<section class="card">
    <header class="card-header"><h2>Zuletzt geprüfte Domains</h2><a class="btn btn-ghost btn-sm" href="/domains">Alle Domains</a></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('globe', 'Keine Domains', '') ?>
        <?php else: ?>
            <table class="table compact">
                <thead><tr><th>Domain</th><th>Letzte Prüfung</th><th class="num">Subdomains</th><th class="num">Offene Findings</th><th>Überwacht</th></tr></thead>
                <tbody>
                <?php foreach ($domains as $d): ?>
                    <tr><td><?= ui_domain_link($d['name'], $d['unicode_name']) ?></td>
                        <td><?= ui_freshness($d['last_checked_at'], $staleHours) ?></td>
                        <td class="num"><?= (int) $d['subdomain_count'] ?></td>
                        <td class="num"><?= (int) $d['open_findings'] ?><?= $d['serious_findings'] > 0 ? ' <span class="badge sev-high">' . (int) $d['serious_findings'] . ' schwer</span>' : '' ?></td>
                        <td><?= $d['monitored'] ? badge('Ja', 'ok') : badge('Nein', 'neutral') ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</section>

<?php if ($activity): ?>
<section class="card">
    <header class="card-header"><h2>Letzte Aktivität</h2></header>
    <div class="card-body flush">
        <ul class="plain-list small activity">
            <?php foreach ($activity as $a): ?>
                <li><span class="muted mono"><?= e(fmt_dt($a['created_at'], 'd.m. H:i')) ?></span> <?= e($a['message']) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
</section>
<?php endif; ?>
